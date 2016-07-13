package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/codegangsta/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "ssh-client"
	app.Usage = "ssh-client [user@]server[:port]"
	app.Action = sshConnection

	app.Run(os.Args)
}

func sshAgent() ssh.AuthMethod {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	}
	return nil
}

func sshConnection(c *cli.Context) error {
	destination := c.Args().Get(0)
	parts := strings.Split(destination, "@")
	user, err := user.Current()
	username := user.Username
	port := "22"
	var server string
	if len(parts) < 2 {
		server = parts[0]
	} else {
		username = parts[0]
		server = parts[1]
		if len(parts) > 2 {
			port = parts[2]
		}
	}

	key, err := ioutil.ReadFile(fmt.Sprintf("%s/.ssh/id_rsa", user.HomeDir))
	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
			sshAgent(),
		},
	}

	// Connect to the remote server and perform the SSH handshake.
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", server, port), config)
	if err != nil {
		log.Fatalf("unable to connect: %v", err)
	}
	defer client.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		panic("Failed to create session: " + err.Error())
	}
	defer session.Close()

	// Set IO
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	in, _ := session.StdinPipe()

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		log.Fatalf("request for pseudo terminal failed: %s", err)
	}

	// Start remote shell
	if err := session.Shell(); err != nil {
		log.Fatalf("failed to start shell: %s", err)
	}

	// Accepting commands
	for {
		reader := bufio.NewReader(os.Stdin)
		str, _ := reader.ReadString('\n')
		if len(str) == 0 {
			fmt.Println("")
			break
		} else if strings.Compare(str, "exit\n") == 0 {
			break
		}
		fmt.Fprint(in, str)
	}
	return nil
}

func scanConfig() string {
	config, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	config = strings.Trim(config, "\n")
	return config
}
