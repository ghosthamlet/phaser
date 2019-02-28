package scanner

func errorsToStr(errs []error) []string {
	ret := make([]string, len(errs))
	for i, err := range errs {
		ret[i] = err.Error()
	}
	return ret
}
