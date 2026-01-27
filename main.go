package main

import (
	"github.com/apollonoid/LoginValidator/jsonapi"
)

func main() {
	jsonapi.ListenAndServe(":8080")
}
