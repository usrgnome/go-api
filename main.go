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
		// seed stuff
		fmt.Println("Seeding the db")
		seedAccounts(store)
	}

	server := NewAPIServer(":3001", store)
	server.Run()
	//fmt.Println("yeah Auddy! %s", err.Error())
}
