package utils

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
