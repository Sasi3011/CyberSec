package middleware

import "encoding/json"

func jsonEncode(w interface{ Write([]byte) (int, error) }, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
