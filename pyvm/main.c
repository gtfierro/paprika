void inc(int *x);

int main() {
    int x = 0;
    inc(&x);
}

void inc(int *x) {
    *x += 1;
}
