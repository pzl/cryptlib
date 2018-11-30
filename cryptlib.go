package cryptlib

import (
	"archive/tar"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/dsnet/compress/bzip2"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh/terminal"
)

var NonMatchingPasswords = errors.New("Passwords did not match")

func Decrypt(enc io.Reader) (io.Reader, error) {
	var source io.Reader
	source = bufio.NewReader(enc)

	// de-PGP armor if needed
	head, err := source.(*bufio.Reader).Peek(11)
	if err != nil {
		return nil, err
	}
	if IsArmored(head) {
		unarmor, err := armor.Decode(source)
		if err != nil {
			return nil, err
		}
		source = unarmor.Body
	}

	// decrypt, ask for password
	failed := false
	msg, err := openpgp.ReadMessage(source, nil,
		func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			if failed {
				// function will just be called again and
				// again for bad passwords. Forever
				// return an error to break out
				fmt.Fprintf(os.Stderr, "\nincorrect. ")
			}
			failed = true

			return PassPrompt("Decryption password")
		}, nil)
	fmt.Fprint(os.Stderr, "\n")

	return msg.UnverifiedBody, err
}

func IsArmored(data []byte) bool {
	return bytes.Equal(data[:11], []byte("-----BEGIN "))
}

func IsTar(data []byte) bool {
	return string(data[0:2]) == "BZ"
}

func Encrypt(plainText io.Reader, pass []byte, compress bool, asciiArmor bool) ([]byte, error) {
	var w io.Writer
	encBuffer := bytes.NewBuffer(nil)
	w = encBuffer
	if asciiArmor {
		armored, err := armor.Encode(encBuffer, "PGP MESSAGE", nil)
		if err != nil {
			return nil, err
		}
		w = armored
	}

	var compression packet.CompressionAlgo
	if compress {
		// note that we can decrypt bzip2
		// https://github.com/golang/crypto/blob/master/openpgp/packet/compressed.go#L55
		// but we can't encrypt with it baked in
		compression = packet.CompressionZLIB
	} else {
		compression = packet.CompressionNone
	}

	// encrypted data->writer, backed by encBuffer buffer (opt. armor passthrough)
	encrypter, err := openpgp.SymmetricallyEncrypt(w, pass, &openpgp.FileHints{
		IsBinary: false, /* @todo write to file */
		FileName: "_CONSOLE",
	}, &packet.Config{
		//DefaultHash:            crypto,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: compression,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
	})
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(encrypter, plainText)
	if err != nil {
		return nil, err
	}
	encrypter.Close()

	if asciiArmor {
		w.(io.WriteCloser).Close()
	}

	return encBuffer.Bytes(), nil
}

func Tarball(startDir string) (io.Reader, error) {
	// tar -cj

	buf := bytes.NewBuffer(nil)

	bz, err := bzip2.NewWriter(buf, &bzip2.WriterConfig{
		Level: 9,
	})
	if err != nil {
		return nil, err
	}
	defer bz.Close()

	tarW := tar.NewWriter(bz)
	defer tarW.Close()

	// write to tarW from files in startDir
	err = filepath.Walk(startDir, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(fi, fi.Name())
		if err != nil {
			return err
		}
		header.Name = file

		err = tarW.WriteHeader(header)
		if err != nil {
			return err
		}

		if !fi.Mode().IsRegular() { // only write contents for normal files
			return nil
		}

		f, err := os.Open(file)
		if err != nil {
			return err
		}

		_, err = io.Copy(tarW, f) // actual writing here
		if err != nil {
			return err
		}

		f.Close() //defer would cause each file handle to wait until all completed
		return nil
	})

	return buf, err
}
func Untar(source io.Reader) error {
	// tar -xjf

	bz, err := bzip2.NewReader(source, nil)
	if err != nil {
		return err
	}
	defer bz.Close()

	tarR := tar.NewReader(bz)

	for {
		header, err := tarR.Next()

		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if header == nil {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			_, err := os.Stat(header.Name)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			err = os.MkdirAll(header.Name, 0755)
			if err != nil {
				return err
			}
		case tar.TypeReg:
			f, err := os.OpenFile(header.Name, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			_, err = io.Copy(f, tarR)
			if err != nil {
				return err
			}

			f.Close()
		}
	}
	return nil
}

func IsEncrypted(filename string) (bool, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		return false, err
	}

	if fi.IsDir() {
		return false, nil
	}

	f, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, 11)
	n, err := io.ReadFull(f, buf)
	if err != io.EOF && err != nil {
		return false, err
	}
	if n == 0 {
		return false, errors.New("read no bytes")
	}

	if IsArmored(buf) {
		return true, nil
	}

	// gpg symmetric 8c0d 0409 0302 https://github.com/file/file/blob/master/magic/Magdir/gnu#L136-L147
	//               8c0d 0407 0302
	// or us:        c32e 0409 0308
	if bytes.Equal(buf[0:2], []byte{0x8c, 0x0d}) || bytes.Equal(buf[0:2], []byte{0xc3, 0x2e}) {
		if buf[2] == 0x04 && buf[4] == 0x03 {
			return true, nil
		}
	}
	return false, nil
}

func DoublePrompt(first string, second string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s: ", first)
	pass, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "\n%s: ", second)
	repass, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Fprint(os.Stderr, "\n")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pass, repass) {
		return nil, NonMatchingPasswords
	}
	return pass, nil
}

func PassPrompt(prompt string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	return terminal.ReadPassword(int(syscall.Stdin))
}
