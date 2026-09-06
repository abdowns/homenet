package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS devices (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	paired_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pairing_codes (
	code       TEXT PRIMARY KEY,
	expires_at INTEGER NOT NULL,
	used       INTEGER NOT NULL DEFAULT 0
);
`

var ErrInvalidCode = errors.New("auth: invalid or expired pairing code")

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("auth: opening %s: %w", path, err)
	}
	// sqlite is single writer; one conn avoids sqlite_busy without needing wal mode
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("auth: migrating schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomHex(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generating random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (s *Store) DeviceCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices`).Scan(&n); err != nil {
		return 0, fmt.Errorf("auth: counting devices: %w", err)
	}
	return n, nil
}

type Device struct {
	ID       string
	Name     string
	PairedAt time.Time
}

func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, paired_at FROM devices ORDER BY paired_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var pairedAt int64
		if err := rows.Scan(&d.ID, &d.Name, &pairedAt); err != nil {
			return nil, err
		}
		d.PairedAt = time.Unix(pairedAt, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) CreatePairingCode(ctx context.Context, ttl time.Duration) (string, error) {
	code, err := randomHex(3)
	if err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO pairing_codes (code, expires_at, used) VALUES (?, ?, 0)`,
		code, time.Now().Add(ttl).Unix()); err != nil {
		return "", fmt.Errorf("auth: storing pairing code: %w", err)
	}
	return code, nil
}

// token is returned only once, the store keeps only its hash
func (s *Store) RedeemPairingCode(ctx context.Context, code, deviceName string) (deviceID, token string, err error) {
	if deviceName == "" {
		return "", "", errors.New("auth: device name is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()

	var expiresAt int64
	var used int
	err = tx.QueryRowContext(ctx, `SELECT expires_at, used FROM pairing_codes WHERE code = ?`, code).
		Scan(&expiresAt, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrInvalidCode
	}
	if err != nil {
		return "", "", err
	}
	if used != 0 || time.Now().Unix() > expiresAt {
		return "", "", ErrInvalidCode
	}
	if _, err := tx.ExecContext(ctx, `UPDATE pairing_codes SET used = 1 WHERE code = ?`, code); err != nil {
		return "", "", err
	}

	id, err := randomHex(8)
	if err != nil {
		return "", "", err
	}
	token, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO devices (id, name, token_hash, paired_at) VALUES (?, ?, ?, ?)`,
		id, deviceName, hashToken(token), time.Now().Unix()); err != nil {
		return "", "", err
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	return id, token, nil
}

func (s *Store) AuthenticateToken(ctx context.Context, token string) (deviceID, deviceName string, ok bool, err error) {
	if token == "" {
		return "", "", false, nil
	}
	err = s.db.QueryRowContext(ctx, `SELECT id, name FROM devices WHERE token_hash = ?`, hashToken(token)).
		Scan(&deviceID, &deviceName)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return deviceID, deviceName, true, nil
}
