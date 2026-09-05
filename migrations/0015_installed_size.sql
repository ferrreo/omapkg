-- Store uncompressed installed bytes from the package's .PKGINFO metadata.
ALTER TABLE builds ADD COLUMN installed_size INTEGER CHECK(installed_size IS NULL OR installed_size >= 0);
