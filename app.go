package main

import (
	"bufio"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/alexmullins/zip"
	"github.com/rs/zerolog/log"
)

var (
//USER = flag.String("user", os.Getenv("USER"), "ssh username")
//HOST = flag.String("host", "localhost", "ssh server hostname")
//HOST = flag.String("host", "dev-shuttle.node.products.internal.dev.navya.cloud", "ssh server hostname")
//HOST = flag.String("host", "192.168.0.101", "ssh server hostname")
//PORT = flag.Int("port", 22, "ssh server port")
//PASS = flag.String("pass", os.Getenv("SOCKSIE_SSH_PASSWORD"), "ssh password")
//SIZE = flag.Int("s", 1<<15, "set max packet size")
)

func main() {
	//err := ZipDirectory("", "", []string{"/tmp/plip"})
	err := ZipDirectory("", "", []string{"/tmp/toto/test2.log"})
	if err != nil {
		log.Error().Err(err).Msg("Error")
	}

}

var (
	sizeBlock = 20
)

func ZipDirectory(logDestAbsolutePath string, filename string, inputFiles []string) error {
	log.Debug().Msgf("Compressing.... %s %s %v ", logDestAbsolutePath, filename, inputFiles)
	/*
		errMkdir := os.MkdirAll(logDestAbsolutePath, os.ModePerm)
		if errMkdir != nil {
			return errMkdir
		}

		zipfilename := fmt.Sprintf("%s/%s.zip", logDestAbsolutePath, filename)
		outFile, err := os.Create(zipfilename)
		if err != nil {
			return err
		}
	*/
	//cmd := exec.Command("ssh 192.168.0.101 'mkdir -p /tmp/toto/ && cat > /tmp/toto/test.zip'")
	//cmd := exec.Command("ssh", "192.168.0.101", "\"cat > /tmp/ZZZZZZZ.zip\"")
	//cmd := exec.Command("/tmp/scp.sh")
	command := "cat <&0 | ssh 192.168.0.101 \"mkdir -p /tmp/taratata && cat > /tmp/taratata/ZZZ2.zip\""
	cmd := exec.Command("bash", "-c", command)
	//cmd := exec.Command("cat", ">", "/tmp/test.zip")
	//cmd := exec.Command("cat")
	writer, _ := cmd.StdinPipe()
	//cmd.Output()

	log.Debug().Msgf("run 1")

	//writer := new(bytes.Buffer)
	zipWriter := zip.NewWriter(writer)

	log.Debug().Msgf("run 2")
	/*defer func() {
		if err := zipWriter.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing zip writer")
		}
		if err := outFile.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing zip file")
		}
	}()*/

	go func() {
		defer func() {
			if err := zipWriter.Close(); err != nil {
				log.Error().Err(err).Msg("Error closing zip writer")
			}
			if err := writer.Close(); err != nil {
				log.Error().Err(err).Msg("Error closing zip file")
			}
		}()
		log.Error().Msgf("run 3")
		err := compress(zipWriter, inputFiles)
		log.Error().Msgf("run 4 %v", err)
	}()

	log.Debug().Msgf("run 5")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Msgf("run 6 %v", err)
	}

	log.Error().Msgf("run 7 %v", out)

	return nil
	/*
		nbFiles := len(inputFiles)
		var errCompress error
		if nbFiles <= sizeBlock {
			log.Debug().Msgf("run 4")
			err := compress(zipWriter, inputFiles)

			log.Error().Msgf("run 5 %v", err)
		} else {
			nbBlocks := nbFiles / sizeBlock
			if nbFiles%sizeBlock > 0 {
				nbBlocks++
			}

			for idBlock := 0; idBlock < nbBlocks && errCompress == nil; idBlock++ {
				idFirst := idBlock * sizeBlock
				idLast := int(math.Min(float64((idBlock+1)*sizeBlock), float64(nbFiles)))
				errCompress = compress(zipWriter, inputFiles[idFirst:idLast])
			}
		}
		return errCompress
	*/
}

func compress(w *zip.Writer, inputFiles []string) error {
	for _, inputFile := range inputFiles {
		if err := addFilesToZip(w, inputFile, ""); err != nil {
			return err
		}
	}
	return nil
}

func before(value string, a string) string {
	pos := strings.LastIndex(value, a)
	if pos == -1 {
		return ""
	}
	adjustedPos := pos + len(a)
	if adjustedPos >= len(value) {
		return ""
	}
	return value[:adjustedPos]
}

func addFilesToZip(w *zip.Writer, basePath, baseInZip string) error {
	isDir, errDir := isPathIsDir(basePath)
	if errDir != nil {
		log.Error().Err(errDir).Msg("Error reading dir")
		return errDir
	}
	var files []fs.FileInfo
	var errReadDir error
	if isDir {
		files, errReadDir = ioutil.ReadDir(basePath)
		if errReadDir != nil {
			return errReadDir
		}
	} else {
		file, err := os.Open(basePath)
		//nolint: staticcheck, errcheck
		defer file.Close()
		if err != nil {
			return err
		}

		fileInfo, err := file.Stat()
		if err != nil {
			return err
		}

		files = append(files, fileInfo)
		basePath = before(basePath, "/")
	}
	return walk(w, basePath, baseInZip, files)
}

func walk(w *zip.Writer, basePath, baseInZip string, files []fs.FileInfo) error {
	for _, file := range files {
		fullfilepath := filepath.Join(basePath, file.Name())
		_, err := os.Stat(fullfilepath)
		if os.IsNotExist(err) || file.Mode()&os.ModeSymlink != 0 {
			// ignore symlinks all together
			// ensure the file exists. For example a symlink pointing to a non-existing location might be listed but not actually exist
			continue
		}

		if file.IsDir() {
			if err := addFilesToZip(w, fullfilepath, filepath.Join(baseInZip, file.Name())); err != nil {
				return err
			}
		} else if file.Mode().IsRegular() {
			/*
				dat, err := ioutil.ReadFile(fullfilepath)
				if err != nil {
					return err
				}
			*/
			//f, err := w.Create(filepath.Join(baseInZip, file.Name()))
			f, err := w.Encrypt(filepath.Join(baseInZip, file.Name()), "AZERTY1234")
			if err != nil {
				return err
			}
			file, err := os.Open(fullfilepath)
			if err != nil {
				return err
			}
			//nolint: staticcheck, errcheck
			defer file.Close()

			fileReader := bufio.NewReader(file)
			_, err = io.Copy(f, fileReader)
			if err != nil {
				return err
			}
			/*
				_, err = f.Write(dat)
				if err != nil {
					return err
				}
			*/
		}
	}
	return nil
}

func isPathIsDir(path string) (bool, error) {
	file, err := os.Open(path)
	//nolint: staticcheck, errcheck
	defer file.Close()
	if err != nil {
		return false, err
	}

	fileInfo, err := file.Stat()
	if err != nil {
		return false, err
	}
	return fileInfo.IsDir(), nil
}

/*
	var conn *ssh.Client
	//authMethod, errAuthMethod := readPublicKey("/home/ubuntu/.ssh/id_ed25519")
	//authMethod, errAuthMethod := readPublicKey("/home/ubuntu/.ssh/dev/id_ed25519-cert.pub")
	authMethod, errAuthMethod := readPublicKey(
		"/home/navya_drive/.ssh/id_ed25519",
		"/home/navya_drive/.ssh/id_ed25519.pub",
		"/home/navya_drive/.ssh/id_ed25519-cert.pub")

	if errAuthMethod != nil {
		log.Fatalf("unable to create auth method : %v", errAuthMethod)
	}
	config := ssh.ClientConfig{
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			log.Default().Println("hostname", hostname)
			log.Default().Println("remote", remote)
			log.Default().Println("key", key)
			return nil
		},
		Auth: authMethod,
		//User: "administrator",
		User: "navya_drive",
	}

	config.Ciphers = append(config.Ciphers, "aes128-ctr", "aes192-ctr", "aes256-ctr", "arcfour256",
		"arcfour128", "aes128-cbc", "3des-cbc", "blowfish-cbc", "cast128-cbc",
		"aes192-cbc", "aes256-cbc", "arcfour", "ed25519")

	addr := fmt.Sprintf("%s:%d", *HOST, *PORT)
	conn, err := ssh.Dial("tcp", addr, &config)
	if err != nil {
		log.Fatalf("unable to connect to [%s]: %v", addr, err)
	}
	defer conn.Close()

	// open an SFTP session over an existing ssh connection.
	client, err := sftp.NewClient(conn)

	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()


	// leave your mark
	f, err := client.Create("/tmp/hello.txt")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := f.Write([]byte("Hello world!")); err != nil {
		log.Fatal(err)
	}
	f.Close()

	// check it's there
	fi, err := client.Lstat("hello.txt")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(fi)


}

func readPublicKey(keypath, pubPath, certPath string) ([]ssh.AuthMethod, error) {
	pKeyBytes, err := ioutil.ReadFile(keypath)
	if err != nil {
		return nil, err
	}
	//signer, err := ssh.ParsePrivateKeyWithPassphrase(pKeyBytes, []byte("Sandra13!*"))
	signer, err := ssh.ParsePrivateKey(pKeyBytes)
	if err != nil {
		return nil, err
	}
	authMethod := ssh.PublicKeys(signer)
	if authMethod == nil {
		log.Fatalf("method is nil 1 %s", err)
		return nil, err
	}

	//ssh.ParsePublicKey()
	pKeyBytes, err = ioutil.ReadFile(certPath)
	if err != nil {
		log.Fatalf("method is nil 1.1 %s", err)
		return nil, err
	}

	cert, _, _, _, err := ssh.ParseAuthorizedKey(pKeyBytes)
	if err != nil {
		log.Fatalf("method is nil 2 %s", err)
		return nil, err
	}

	// create a signer using both the certificate and the private key:
	certSigner, err := ssh.NewCertSigner(cert.(*ssh.Certificate), signer)
	if err != nil {
		log.Fatalf("method is nil 3 %s", err)
		return nil, err
	}

	authMethodCert := ssh.PublicKeys(certSigner)
	if authMethodCert == nil {
		log.Fatalf("method is nil 4")
		return nil, nil
	}

	return []ssh.AuthMethod{
		authMethod,
		authMethodCert,
	}, nil
}
*/
