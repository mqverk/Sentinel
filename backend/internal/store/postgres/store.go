package postgres

import (
	"errors"

	"sentinel/backend/internal/store"
)

func New(_ string) (store.Store, error) {
	return nil, errors.New("postgres store is not implemented yet")
}
