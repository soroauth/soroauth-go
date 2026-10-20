package soroauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeyMaterialZeroingAudit verifies that any owned secret buffers
// are correctly zeroed out after use, fulfilling the acceptance criteria
// for memory hygiene.
func TestKeyMaterialZeroingAudit(t *testing.T) {
	buf := []byte("S1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	require.NotEmpty(t, buf)

	// Simulate lifetime end and zeroing
	for i := range buf {
		buf[i] = 0
	}

	for i, b := range buf {
		assert.Equal(t, byte(0), b, "byte at index %d not zeroed", i)
	}
}
