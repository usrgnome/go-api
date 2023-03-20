package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Storage interface {
	CreateAccount(*Account) error
	DeleteAccount(int) error
	UpdateAccount(*Account) error
	GetAccountByID(int) (*Account, error)
	GetAccounts() ([]*Account, error)
	GetAccountByEmail(string) (*Account, error)
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	connStr := "user=postgres dbname=postgres password=mysecretpassword sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgresStore{
		db: db,
	}, nil
}

func (s *PostgresStore) CreateAccount(acc *Account) error {
	query := `
	insert into account
	(username, email, encrypted_password, created_at)
	values ($1, $2, $3, $4)
	`
	_, err := s.db.Query(
		query,
		acc.Username,
		acc.Email,
		acc.EncryptedPassword,
		acc.CreatedAt,
	)

	if err != nil {
		return err
	}

	return nil
}
func (s *PostgresStore) UpdateAccount(*Account) error {
	return nil
}
func (s *PostgresStore) DeleteAccount(id int) error {
	_, err := s.db.Query("delete from account where id = $1", id)
	return err
}

func (s *PostgresStore) GetAccountByEmail(email string) (*Account, error) {
	rows, err := s.db.Query("select * from account WHERE email = $1", email)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		return scanIntoAccount(rows)
	}

	return nil, fmt.Errorf("account %s not found", email)
}

func (s *PostgresStore) GetAccountByID(id int) (*Account, error) {
	rows, err := s.db.Query("select * from account WHERE id = $1", id)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		return scanIntoAccount(rows)
	}

	return nil, fmt.Errorf("account %d not found", id)
}

func (s *PostgresStore) GetAccounts() ([]*Account, error) {
	rows, err := s.db.Query("select * from account")
	if err != nil {
		return nil, err
	}

	accounts := []*Account{}

	for rows.Next() {
		account, err := scanIntoAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (s *PostgresStore) Init() error {
	return s.createAccountTable()
}

func (s *PostgresStore) createAccountTable() error {
	query := `create table if not exists account (
		id serial primary key,
		username varchar(50),
		email varchar(50),
		encrypted_password varchar(100),
		created_at timestamp
	)`

	_, err := s.db.Exec(query)
	return err
}

func scanIntoAccount(rows *sql.Rows) (*Account, error) {
	account := new(Account)
	err := rows.Scan(
		&account.ID,
		&account.Username,
		&account.Email,
		&account.EncryptedPassword,
		&account.CreatedAt,
	)

	return account, err
}
