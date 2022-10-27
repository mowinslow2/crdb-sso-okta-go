package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/cockroachdb/cockroach-go/v2/crdb/crdbpgx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
)

func insertRows(ctx context.Context, tx pgx.Tx, accts [4]uuid.UUID) error {
	// Insert four rows into the "accounts" table.
	log.Println("Creating new rows...")
	if _, err := tx.Exec(ctx,
		"INSERT INTO accounts (id, balance) VALUES ($1, $2), ($3, $4), ($5, $6), ($7, $8)", accts[0], 250, accts[1], 100, accts[2], 500, accts[3], 300); err != nil {
		return err
	}
	return nil
}

func printBalances(conn *pgx.Conn) error {
	rows, err := conn.Query(context.Background(), "SELECT id, balance FROM accounts")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var balance int
		if err := rows.Scan(&id, &balance); err != nil {
			log.Fatal(err)
		}
		log.Printf("%s: %d\n", id, balance)
	}
	return nil
}

func transferFunds(ctx context.Context, tx pgx.Tx, from uuid.UUID, to uuid.UUID, amount int) error {
	// Read the balance.
	var fromBalance int
	if err := tx.QueryRow(ctx,
		"SELECT balance FROM accounts WHERE id = $1", from).Scan(&fromBalance); err != nil {
		return err
	}

	if fromBalance < amount {
		log.Println("insufficient funds")
	}

	// Perform the transfer.
	log.Printf("Transferring funds from account with ID %s to account with ID %s...", from, to)
	if _, err := tx.Exec(ctx,
		"UPDATE accounts SET balance = balance - $1 WHERE id = $2", amount, from); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		"UPDATE accounts SET balance = balance + $1 WHERE id = $2", amount, to); err != nil {
		return err
	}
	return nil
}

func deleteRows(ctx context.Context, tx pgx.Tx, one uuid.UUID, two uuid.UUID) error {
	// Delete two rows into the "accounts" table.
	log.Printf("Deleting rows with IDs %s and %s...", one, two)
	if _, err := tx.Exec(ctx,
		"DELETE FROM accounts WHERE id IN ($1, $2)", one, two); err != nil {
		return err
	}
	return nil
}

// Standard response format from Okta
type OktaResponse struct {
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`   // Not used in this demo
	ExpiresIn    int    `json:"expires_in"`   // Not used in this demo
	AccessToken  string `json:"access_token"` // Not used in this demo
	Scope        string `json:"scope"`        // Not used in this demo
}

/*
	Returns new refresh_token and id_token

	http --form POST https://${yourOktaDomain}/oauth2/default/v1/token \
	accept:application/json \
	authorization:'Basic MG9hYmg3M...' \
	cache-control:no-cache \
	content-type:application/x-www-form-urlencoded \
	grant_type=refresh_token \
	redirect_uri=http://localhost:8080 \
	scope=offline_access%20openid \
	refresh_token=MIOf-U1zQbyfa3MUfJHhvnUqIut9ClH0xjlDXGJAyqo
*/
func useRefreshToken(refreshToken string, oktaUrl string, clientID string, clientSecret string) (string, string) {
	form := url.Values{}
	form.Add("grant_type", "refresh_token")
	form.Add("scope", "openid offline_access")
	form.Add("refresh_token", refreshToken) // Use instead of username/password

	req, err := http.NewRequest("POST", oktaUrl, strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var result OktaResponse
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result.IdToken, result.RefreshToken
}

/*
	Return id_token AND refresh_token to be used later

	curl --location --request POST 'https://${yourOktaDomain}/oauth2/default/v1/token' \
	-H 'Accept: application/json' \
	-H 'Authorization: Basic ${Base64(${clientId}:${clientSecret})}' \
	-H 'Content-Type: application/x-www-form-urlencoded' \
	-d 'grant_type=password' \
	-d 'redirect_uri=${redirectUri}' \
	-d 'username=example@mailinator.com' \
	-d 'password=a.gReAt.pasSword' \
	-d 'scope=openid offline_access'
*/
func getTokens(oktaUrl string, clientID string, clientSecret string, oktaUsername string, oktaPassword string) (string, string) {
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("scope", "openid offline_access")
	form.Add("username", oktaUsername)
	form.Add("password", oktaPassword)

	req, err := http.NewRequest("POST", oktaUrl, strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var result OktaResponse
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result.IdToken, result.RefreshToken
}

/*
	Return new id_token only. Not currently in use by program.
	Can be used as standalone instead of getTokens() + useRefreshToken()

	curl --location --request POST 'https://${yourOktaDomain}/oauth2/default/v1/token' \
	-H 'Accept: application/json' \
	-H 'Authorization: Basic ${Base64(${clientId}:${clientSecret})}' \
	-H 'Content-Type: application/x-www-form-urlencoded' \
	-d 'grant_type=password' \
	-d 'username=example@mailinator.com' \
	-d 'password=a.gReAt.pasSword' \
	-d 'scope=openid'
*/
func getIDToken(oktaUrl string, clientID string, clientSecret string, oktaUsername string, oktaPassword string) string {
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("scope", "openid")
	form.Add("username", oktaUsername)
	form.Add("password", oktaPassword)

	req, err := http.NewRequest("POST", oktaUrl, strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var result OktaResponse
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result.IdToken
}

func executeWorkload(idToken string) {
	// Update the next 3 variables in order to complete your DB connection string
	sqlUser := "sqlUser"
	host := "host"
	cert := "/ca.cert"
	dbURL := "postgresql://" + sqlUser + ":" + idToken + "@" + host + ":26257/defaultdb?sslmode=verify-full&sslrootcert=" + cert + "&options=--crdb:jwt_auth_enabled=true"
	config, err := pgx.ParseConfig(dbURL)
	if err != nil {
		log.Fatal(err)
	}

	config.RuntimeParams["application_name"] = "$ docs_simplecrud_gopgx"
	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close(context.Background())

	// Insert initial rows
	var accounts [4]uuid.UUID
	for i := 0; i < len(accounts); i++ {
		accounts[i] = uuid.New()
	}

	err = crdbpgx.ExecuteTx(context.Background(), conn, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return insertRows(context.Background(), tx, accounts)
	})
	if err == nil {
		log.Println("New rows created.")
	} else {
		log.Fatal("error: ", err)
	}

	// Print out the balances
	log.Println("Initial balances:")
	//printBalances(conn)

	// Run a transfer
	err = crdbpgx.ExecuteTx(context.Background(), conn, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return transferFunds(context.Background(), tx, accounts[2], accounts[1], 100)
	})
	if err == nil {
		log.Println("Transfer successful.")
	} else {
		log.Fatal("error: ", err)
	}

	// Print out the balances
	log.Println("Balances after transfer:")
	//printBalances(conn)

	// Delete rows
	err = crdbpgx.ExecuteTx(context.Background(), conn, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return deleteRows(context.Background(), tx, accounts[0], accounts[1])
	})
	if err == nil {
		log.Println("Rows deleted.")
	} else {
		log.Fatal("error: ", err)
	}

	// Print out the balances
	log.Println("Balances after deletion:")
	printBalances(conn)
}

func main() {
	// Env variables
	oktaUrl := os.Getenv("OKTA_URL")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	oktaUsername := os.Getenv("OKTA_USERNAME")
	oktaPassword := os.Getenv("PASSWORD")

	// Get id_token to make request. Save refresh_token for future request
	idToken, refreshToken := getTokens(oktaUrl, clientID, clientSecret, oktaUsername, oktaPassword)
	executeWorkload(idToken)

	fmt.Println("------------------------------------------------------------")
	fmt.Println("--------- USING refresh_token TO GRAB NEW id_token ---------")
	fmt.Println("------------------------------------------------------------")

	// Utilize saved refresh_token to get new id_token. No need for username/password here
	newIDToken, newRefreshToken := useRefreshToken(refreshToken, oktaUrl, clientID, clientSecret)
	os.Setenv("REFRESH_TOKEN", newRefreshToken) // Save refresh_token in env var to be used in the future across the app
	executeWorkload(newIDToken)
}
