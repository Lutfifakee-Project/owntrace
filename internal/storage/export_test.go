package storage

// execForTest runs raw SQL for tamper simulations (test-only backdoor;
// lives in an export_test.go file so it never ships in production builds).
func (d *DB) execForTest(query string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec(query)
	return err
}
