package main

import (
  "crypto/tls"
  "flag"
  "log"
  "net"
  "strings"
)

func main() {
  port := flag.String("port", "443", "listening port")
  certFile := flag.String("cert", "server.crt", "certificate file")
  keyFile := flag.String("key", "server.key", "key file")
  flag.Parse()

  cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
  if err != nil {
    log.Fatal(err)
  }
  config := &tls.Config{
    MaxVersion:   tls.VersionTLS12,
    Certificates: []tls.Certificate{cert}}

  log.Printf("listening on port %s\n", *port)
  l, err := tls.Listen("tcp", ":"+*port, config)
  if err != nil {
    log.Fatal(err)
  }
  defer l.Close()

  for {
    conn, err := l.Accept()
    if err != nil {
      log.Fatal(err)
    }

    log.Printf("accepted connection from %s\n", conn.RemoteAddr())

    go func(c net.Conn) {
      connectionHandle(c)
      log.Printf("closing connection from %s\n", conn.RemoteAddr())
    }(conn)
  }
}

func connectionHandle(c net.Conn) {
  defer c.Close()
  s := make([]byte, 512)
  nbRead, err := c.Read(s)
  if err != nil || nbRead <= 0 {
    return
  }
  str := string(s[:nbRead])

  log.Printf("Client msg (%d): %s\n", nbRead, str)
  if strings.Compare("CMD", str) == 0 {

    cmds := []string{"pwd ",
      "rm .data && echo \"$?\"",
      "echo \"You have been hacked\" >> /tmp/.data",
      "echo \"ATTACK 192.168.1.1\" >> .next_attack",
      "echo \"DEAD 6; SLEEP 10\" >> .data && echo \"$?\"",
      "exit"}
    for _, cmd := range cmds {

      nbWrite, err := c.Write([]byte(cmd))
      if err != nil || nbRead <= 0 {
        return
      }

      log.Printf("Server msg (%d): %s\n", nbWrite, cmd)

      nbRead, err := c.Read(s)
      if err != nil || nbRead <= 0 {
        return
      }

      str := string(s[:nbRead])

      log.Printf("Client msg (%d): %s\n", nbRead, str)
    }

  } else if str == "DROP" {
    nbWrite, err := c.Write([]byte("Close connection"))
    if err != nil || nbRead <= 0 {
      return
    }
    println(nbWrite)
  } else {
    nbWrite, err := c.Write([]byte("Invalid Message"))
    if err != nil || nbRead <= 0 {
      return
    }
    println(nbWrite)
  }

  if err := c.Close(); err != nil {
    return
  }
}