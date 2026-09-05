package kms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type fakeKMS struct {
	key       *rsa.PrivateKey
	created   time.Time
	lastInput *kms.SignInput
}

func (f *fakeKMS) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{PublicKey: der}, nil
}

func (f *fakeKMS) DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return &kms.DescribeKeyOutput{KeyMetadata: &types.KeyMetadata{
		CreationDate: aws.Time(f.created), KeyUsage: types.KeyUsageTypeSignVerify,
	}}, nil
}

func (f *fakeKMS) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.lastInput = input
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, input.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: signature}, nil
}

func TestKMSBackendProducesGnuPGSignature(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg is not installed")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeKMS{key: key, created: time.Unix(1700000000, 0).UTC()}
	backend, err := NewWithClient(context.Background(), fake, "arn:aws:kms:eu-west-1:123:key/test")
	if err != nil {
		t.Fatal(err)
	}
	public, err := backend.PublicKeyArmor(context.Background(), "omarpkg", "packages@example.com")
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("package bytes\x00\n")
	signature, err := backend.SignDetached(context.Background(), strings.NewReader(string(message)))
	if err != nil {
		t.Fatal(err)
	}
	if fake.lastInput == nil || fake.lastInput.MessageType != types.MessageTypeDigest || fake.lastInput.SigningAlgorithm != types.SigningAlgorithmSpecRsassaPkcs1V15Sha256 {
		t.Fatalf("unexpected KMS input: %#v", fake.lastInput)
	}
	if len(fake.lastInput.Message) != sha256.Size {
		t.Fatalf("KMS received %d-byte digest", len(fake.lastInput.Message))
	}

	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(home, "opr-key.asc")
	messagePath := filepath.Join(home, "package.pkg.tar.zst")
	signaturePath := messagePath + ".sig"
	if err := os.WriteFile(publicPath, public, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(messagePath, message, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--import", publicPath}, {"--verify", signaturePath, messagePath}} {
		cmd := exec.Command("gpg", append([]string{"--batch", "--homedir", home}, args...)...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("gpg %v: %v\n%s", args, err, output)
		}
		if args[0] == "--verify" && !strings.Contains(string(output), "Good signature") {
			t.Fatalf("gpg did not report a good signature: %s", output)
		}
	}
	if !strings.Contains(string(public), "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatal("public key is not armored")
	}
}

func TestKMSBackendRejectsNonSHA256Digest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeKMS{key: key, created: time.Unix(1700000000, 0).UTC()}
	backend, err := NewWithClient(context.Background(), fake, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.SignDigest(context.Background(), make([]byte, 31)); err == nil {
		t.Fatal("short digest was accepted")
	}
	if fake.lastInput != nil {
		t.Fatal("KMS was called for invalid digest")
	}
}
