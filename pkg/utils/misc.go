package utils

import "log"

func EitherOr[T any](condition bool, x, y T) T {
	if condition {
		return x
	}

	return y
}

func EitherOrFunc[T any](condition bool, f func() T, y T) T {
	if condition {
		return f()
	}

	return y
}

func IfEmptyStr(text, fallBack string) string {
	if text != "" {
		return text
	}

	return fallBack
}

// ExitOnError Check error and if error is not nil, Log the error and exit
func ExitOnError(err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}
}
