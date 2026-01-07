package main

import (
	"fmt"
	"log"
	"os"
)

func packetLogger(v any) error {
	file, err := os.OpenFile("./logs/test.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		fmt.Println("Error opening file")
		return err
	}
	defer file.Close()

	log.SetOutput(file)

	log.Println(v)

	return nil
}
