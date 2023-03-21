package main

import (
	"flag"
	"fmt"
	"log"
)

func seedAccount(store Storage, fname, lname, pw string) *Account {
	acc, err := NewAccount(fname, lname, pw)
	if err != nil {
		log.Fatal(err)
	}

	if err := store.CreateAccount(acc); err != nil {
		log.Fatal(err)
	}

	fmt.Println("new account => ", acc.ID)

	return acc
}

func seedAccounts(s Storage) {
	seedAccount(s, "sam", "ha", "pass")
}

func main() {
	seed := flag.Bool("seed", false, "seed the db")
	port := flag.String("port", "3000", "--port=3000")
	flag.Parse()

	store, err := NewPostgresStore()
	if err != nil {
		log.Fatal(err)
		return
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	if *seed {
		fmt.Println("Seeding the db")
		seedAccounts(store)
	}

	PrintSecrets()

	formattedPort := ":" + *port
	server := NewAPIServer(formattedPort, store)
	server.Run()
}
