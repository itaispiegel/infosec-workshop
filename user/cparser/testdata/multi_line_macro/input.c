#define swap(a, b) {               \
                       (a) ^= (b); \
                       (b) ^= (a); \
                       (a) ^= (b); \
                   }

int main() {
    int x = 2;
    int y = 3;
    swap(x, y);
}
