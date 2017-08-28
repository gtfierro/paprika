int x[3];

void inc(int *x) {
    *x += 1;
}

int main() {
    for (int i=0; i<3; i++) {
        x[i] = i;
        inc(&x[i]);
    }

    int sum = 0;
    for (int i=0; i<3; i++) {
        sum += x[i];
    }

    return sum;
}
