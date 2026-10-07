package component

import (
	"testing"

	"github.com/leslie-qiwa/flat"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/dataformat"
	"github.com/stretchr/testify/require"
)

func TestFlatMap_FlattenUnflatten(t *testing.T) {
	data := map[string]interface{}{
		"foo": "bar",
		"bar": map[string]interface{}{
			"baz": "foo",
		},
		"slice": []interface{}{
			"foo",
			"bar",
		},
		"with.dot": map[string]interface{}{
			"foo": "bar",
		},
	}

	opts := &flat.Options{
		Safe:      true,
		Delimiter: "~",
	}
	flattened, err := flat.Flatten(data, opts)
	if err != nil {
		t.Fatal(err)
	}

	nested, err := flat.Unflatten(flattened, opts)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, data, nested, "unexpected data")
}

func TestAnySlice(t *testing.T) {
	data := []any{}
	data = append(data, []int{1, 2, 3})
	data = append(data, []string{"foo", "bar"})
	data = append(data, []bool{true, false})
	data = append(data, []float64{1.1, 2.2, 3.3})

	for _, d := range data {
		val, ok := IsTypedSlice(d)
		require.True(t, ok, "expected slice")
		require.True(t, val != nil, "expected value but got nil")
	}
}

func TestSetParsedValue_EmptyMap(t *testing.T) {
	// Empty objects ({}) survive flattening as map values. Fuzzing such a key
	// must inject the payload (type-confusion probe), not warn + resend the
	// original body while reporting success.
	body := `{"platform":"ANDROID","empty":{},"name":"x"}`
	kv, err := dataformat.Get("json").Decode(body)
	require.NoError(t, err)

	v := &Value{}
	v.encoder = dataformat.Get("json")
	v.SetParsed(kv, "json")

	require.True(t, v.SetParsedValue("empty", "PAYLOAD"), "empty map should accept payload")
	enc, err := v.Encode()
	require.NoError(t, err)
	require.Contains(t, enc, `"empty":"PAYLOAD"`, "payload must replace empty object, got: %s", enc)
	require.NotContains(t, enc, `"empty":{}`, "original body must not be resent")
}

func TestSetParsedValue_UnknownTypeFails(t *testing.T) {
	// Genuinely unsettable types must return false so the caller skips the
	// point (ErrSetValue) instead of sending an unfuzzed duplicate.
	v := &Value{}
	v.SetParsed(dataformat.KVMap(map[string]interface{}{"odd": map[string]string{"a": "b"}}), "json")
	require.False(t, v.SetParsedValue("odd", "PAYLOAD"), "unknown map type must fail, not fake success")
}
