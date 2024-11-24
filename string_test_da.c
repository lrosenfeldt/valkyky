void stringInit(string_t *str) {
	daInit(str);
	return;
}

void stringDrop(string_t *str) {
	daDrop(str);
	return;
}

void stringClear(string_t *str) {
	daClear(str);
	return;
}

int stringGrow(string_t *str, size_t cap) {
	return daGrow(str, cap);
}

void stringPut(string_t *str, char ch) {
	daPut(str, ch);
	return;
}

void stringPutN(string_t *str, const char *buffer, size_t n) {
	daPutN(str, buffer, n);
	return;
}
