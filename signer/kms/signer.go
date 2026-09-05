// Package kms adapts an AWS KMS RSA signing key to pacman-compatible OpenPGP.
// The KMS private key is never downloaded or materialized in this process.
package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256"

// API is the subset of the KMS client used by Backend. It keeps tests offline.
type API interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// Backend signs OpenPGP digests with an RSA key held by KMS.
type Backend struct {
	client  API
	keyARN  string
	public  *rsa.PublicKey
	created time.Time
}

// New loads AWS credentials through the standard SDK chain and validates key
// identity before returning a backend. It requires an explicit KMS key ARN.
func New(ctx context.Context, region, keyARN string) (*Backend, error) {
	if region == "" || keyARN == "" {
		return nil, errors.New("AWS region and KMS key ARN are required")
	}
	config, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return NewWithClient(ctx, kms.NewFromConfig(config), keyARN)
}

// NewWithClient validates the KMS public key and creation time. It is used by
// tests with a fake KMS API and by callers that already own an SDK client.
func NewWithClient(ctx context.Context, client API, keyARN string) (*Backend, error) {
	if client == nil || keyARN == "" {
		return nil, errors.New("KMS client and key ARN are required")
	}
	publicKey, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyARN)})
	if err != nil {
		return nil, fmt.Errorf("get KMS public key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse KMS public key: %w", err)
	}
	rsaPublic, ok := parsed.(*rsa.PublicKey)
	if !ok || rsaPublic.N == nil || rsaPublic.E <= 1 || rsaPublic.N.BitLen() < 2048 {
		return nil, errors.New("KMS key must be an RSA key of at least 2048 bits")
	}
	described, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyARN)})
	if err != nil {
		return nil, fmt.Errorf("describe KMS key: %w", err)
	}
	if described.KeyMetadata == nil || described.KeyMetadata.CreationDate == nil {
		return nil, errors.New("KMS key has no creation date")
	}
	if string(described.KeyMetadata.KeyUsage) != string(types.KeyUsageTypeSignVerify) {
		return nil, errors.New("KMS key usage must be SIGN_VERIFY")
	}
	return &Backend{client: client, keyARN: keyARN, public: rsaPublic, created: described.KeyMetadata.CreationDate.UTC()}, nil
}

func (b *Backend) PublicKey() *rsa.PublicKey { return b.public }
func (b *Backend) CreationTime() time.Time   { return b.created }
func (b *Backend) KeyARN() string            { return b.keyARN }

func (b *Backend) Fingerprint() ([]byte, error) {
	pub := packet.NewRSAPublicKey(b.created, b.public)
	if len(pub.Fingerprint) != 20 {
		return nil, errors.New("invalid OpenPGP fingerprint")
	}
	return append([]byte(nil), pub.Fingerprint...), nil
}

// SignDigest implements the crypto.Signer digest contract. AWS KMS receives
// the OpenPGP-computed digest and applies EMSA-PKCS1-v1_5 SHA-256 itself.
func (b *Backend) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("SHA-256 digest has %d bytes", len(digest))
	}
	result, err := b.client.Sign(ctx, &kms.SignInput{
		KeyId: aws.String(b.keyARN), Message: digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS sign: %w", err)
	}
	if len(result.Signature) != b.public.Size() {
		return nil, fmt.Errorf("KMS returned %d-byte RSA signature, want %d", len(result.Signature), b.public.Size())
	}
	return append([]byte(nil), result.Signature...), nil
}

type remoteSigner struct {
	backend *Backend
	ctx     context.Context
}

func (s remoteSigner) Public() crypto.PublicKey { return s.backend.public }
func (s remoteSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("unsupported OpenPGP hash %v", opts.HashFunc())
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return s.backend.SignDigest(ctx, digest)
}

// PublicKeyArmor returns a stable v4 OpenPGP certificate containing only the
// KMS public key, a project identity, and its KMS-made self-certification.
func (b *Backend) PublicKeyArmor(ctx context.Context, name, email string) ([]byte, error) {
	if name == "" || email == "" {
		return nil, errors.New("OpenPGP name and email are required")
	}
	pub := packet.NewRSAPublicKey(b.created, b.public)
	priv := &packet.PrivateKey{PublicKey: *pub, PrivateKey: remoteSigner{backend: b, ctx: ctx}}
	uid := packet.NewUserId(name, "", email)
	if uid == nil {
		return nil, errors.New("invalid OpenPGP user ID")
	}
	primary := true
	cert := &packet.Signature{
		Version: 4, SigType: packet.SigTypePositiveCert,
		PubKeyAlgo: packet.PubKeyAlgoRSA, Hash: crypto.SHA256,
		CreationTime: b.created, IsPrimaryId: &primary,
		FlagsValid: true, FlagCertify: true, FlagSign: true,
	}
	config := &packet.Config{Rand: rand.Reader, DefaultHash: crypto.SHA256, Time: func() time.Time { return b.created }}
	if err := cert.SignUserId(uid.Id, pub, priv, config); err != nil {
		return nil, fmt.Errorf("self-certify OpenPGP key: %w", err)
	}
	var raw bytes.Buffer
	if err := pub.Serialize(&raw); err != nil {
		return nil, err
	}
	if err := uid.Serialize(&raw); err != nil {
		return nil, err
	}
	if err := cert.Serialize(&raw); err != nil {
		return nil, err
	}
	var armored bytes.Buffer
	writer, err := armor.Encode(&armored, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(raw.Bytes()); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return armored.Bytes(), nil
}

// SignDetached emits a binary OpenPGP detached signature for a seekable
// artifact. It verifies the serialized packet locally before returning it.
func (b *Backend) SignDetached(ctx context.Context, input io.ReadSeeker) ([]byte, error) {
	if input == nil {
		return nil, errors.New("artifact is required")
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	messageHash := sha256.New()
	if _, err := io.Copy(messageHash, input); err != nil {
		return nil, fmt.Errorf("hash artifact: %w", err)
	}
	created := time.Now().UTC().Truncate(time.Second)
	pub := packet.NewRSAPublicKey(b.created, b.public)
	priv := &packet.PrivateKey{PublicKey: *pub, PrivateKey: remoteSigner{backend: b, ctx: ctx}}
	sig := &packet.Signature{Version: 4, SigType: packet.SigTypeBinary, PubKeyAlgo: packet.PubKeyAlgoRSA, Hash: crypto.SHA256, CreationTime: created}
	config := &packet.Config{Rand: rand.Reader, DefaultHash: crypto.SHA256, Time: func() time.Time { return created }}
	if err := sig.Sign(messageHash, priv, config); err != nil {
		return nil, err
	}
	var serialized bytes.Buffer
	if err := sig.Serialize(&serialized); err != nil {
		return nil, err
	}
	parsed, err := packet.NewReader(bytes.NewReader(serialized.Bytes())).Next()
	if err != nil {
		return nil, fmt.Errorf("parse generated signature: %w", err)
	}
	parsedSignature, ok := parsed.(*packet.Signature)
	if !ok {
		return nil, errors.New("generated output is not a signature packet")
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	verifyHash := sha256.New()
	if _, err := io.Copy(verifyHash, input); err != nil {
		return nil, err
	}
	if err := pub.VerifySignature(verifyHash, parsedSignature); err != nil {
		return nil, fmt.Errorf("verify generated signature: %w", err)
	}
	return serialized.Bytes(), nil
}

func (b *Backend) String() string {
	fingerprint, err := b.Fingerprint()
	if err != nil {
		return b.keyARN
	}
	return b.keyARN + "/" + hex.EncodeToString(fingerprint)
}
