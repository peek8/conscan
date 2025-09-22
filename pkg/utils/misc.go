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

func IfThen(condition bool, f func()) {
	if condition {
		f()
	}
}

func AppendIf[T any](condition bool, elements []T, elem T) []T {
	if condition {
		return append(elements, elem)
	}

	return elements
}

func IfEmptyStr(text, fallBack string) string {
	if text != "" {
		return text
	}

	return fallBack
}

func IsEmptyArray[T any](xs []T) bool {
	return len(xs) == 0
}

func IsNotEmptyArray[T any](xs []T) bool {
	return !IsEmptyArray(xs)
}

// ExitOnError Check error and if error is not nil, Log the error and exit
func ExitOnError(err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}
}
