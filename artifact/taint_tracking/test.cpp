#include <iostream>
#include <fstream>
#include <filesystem>
#include <system_error>
#include <cassert>
#include <vector>

void open_file(std::filesystem::path const &path) {
    // Try to determine the file size. If unknown, just mark it as unknown.
    std::error_code ec;
    uint64_t size = std::filesystem::file_size(path, ec);
    if (ec) {
        std::cout << "[*] Test error: " << ec.message() << std::endl;
    }
    std::cout << "[*] Test: file size is " << size << std::endl;
}

bool load_magic(char *path, char *magic) {
    FILE* file = fopen(path, "r");
    if (!file) {
        perror("[!] Test: Cannot open file");
        return false;
    }
    fgets(magic, sizeof(magic), file);
    fclose(file);
    return true;
}

extern "C"
int *load(int *array, int index) {
    return &array[index];
}

extern "C"
int *apply(int *function(int*, int), int *array, int index) {
    return function(array, index);
}

extern "C"
bool stack_taint_test(char *magic) {
    char a = magic[4];
    char b = magic[5];
    char c = a + b;
    printf("[*] Test: c = %c\n", c);

    return true;
}

extern "C"
bool heap_taint_test(char *magic) {
    int *array = (int *) malloc(sizeof(int) * 32);
    int *a = &array[0];
    int *b = apply(load, array, 1);
    int *c = &array[2];
    float *d = (float *) &array[3];

    printf("[*] Test: b = %p\n", b);

    *b = 1;
    *c = magic[0];
    *d = magic[1];
    int x = *a + *b + *c + *d;
    printf("[*] Test: x = %d\n", x);

    return true;
}

extern "C"
bool heap_taint_test2() {
    struct Pair {
        int* a;
        int* b;
    };
    struct Pair *pair = (struct Pair *) malloc(sizeof(struct Pair));
    pair->a = (int *) malloc(sizeof(int));
    pair->b = (int *) malloc(sizeof(int));
    *pair->a = 1;
    int c = *pair->a + *pair->b;
    printf("[*] Test: heap_taint_test2.c = %d\n", c);
    free(pair->a);
    free(pair->b);
    free(pair);
    return true;
}

class Dict
{
private:
    int id;
public:
    Dict(int id) {
        this->id = id;
    }
};

enum ObjType
{
    // simple objects
    objBool, // boolean
    objInt, // integer
    objReal, // real
    objString, // string
    objDict=7, // dictionary
    objStream=8, // stream
    objNone=13, // uninitialized object
    objDead=17, // and object after shallowCopy
};

#define CHECK_NOT_DEAD                                                                                                                                                                                                                         \
    if (type == objDead) {                                                                                                                                                                                                           \
        puts("Call to dead object");                                                                                                                                                                                          \
        abort();                                                                                                                                                                                                                               \
    }
class Object
{
public:
    Object() : type(objNone) { }
    ~Object() { free(); }

    explicit Object(bool boolnA)
    {
        puts("[*] Object::Object() type = objBool;");
        type = objBool;
        booln = boolnA;
    }
    explicit Object(int *intgA)
    {
        type = objInt;
        intg = *intgA;
    }
    explicit Object(Dict *dictA)
    {
        type = objDict;
        dict = dictA;
    }

    bool isStream() const
    {
        CHECK_NOT_DEAD;
        return type == objStream;
    }

    // Free object contents.
    void free() {}

    ObjType type; // object type
    union { // value for each type:
        bool booln; //   boolean
        int intg; //   integer
        Dict *dict; //   dictionary
    };
};

Object getDict(bool is_master) {
    Object obj;
    if (is_master) {
        obj = Object(new Dict(0));
        return obj;
    } else {
        return Object(new Dict(1));
    }
}

extern "C"
bool class_taint_test() {
    Object obj1 = Object(true);
    obj1.booln = false;
    printf("[*] Test: obj1 = %p\n", &obj1);

    int *a = (int *) malloc(sizeof(int));
    *a = obj1.type;
    Object *obj2 = new Object(a);
    printf("[*] Test: obj2->type = %p\n", &obj2->type);
    printf("[*] Test: obj2->isStream() = %d\n", obj2->isStream());

    Object obj3 = getDict(true);
    printf("[*] Test: obj3->isStream() = %d\n", obj3.isStream());
    std::vector<Object> objs;
    objs.push_back(obj3);
    objs[0].free();

    return true;
}

extern "C"
bool struct_test() {
    struct Pair {
        int a;
        int b;
    } s;
    s.a = 1;
    s.b = 2;
    printf("[*] Test: s.a = %d, s.b = %d\n", s.a, s.b);

    return true;
}

#pragma optimize("", on)
extern "C"
bool memcpy_test() {
    char *src = (char *) malloc(8);
    src[0] = 'a'; // store
    src[1] = 'b'; // store 
    char *dest = (char *) malloc(8);
    std::memcpy(dest, src, 8); // llvm.memcpy
    free(src);
    printf("[*] Test: memcpy: dest = %s\n", dest);

    return true;
}
#pragma optimize("", off)

extern "C"
bool dominator_test() {
    int *a = (int *) malloc(sizeof(int));
    int *b = (int *) malloc(sizeof(int));
    int *c = (int *) malloc(sizeof(int));
    *a = 1;
    *b = 2;
    *c = 3;
    if (*c) {
        if (*b) {
            volatile bool result = !!*a;
        }
    }
    return true;
}

extern "C"
int TIFFGetField(int *v, ...)
{
    int status = 1;
    va_list ap;
    va_start(ap, v);
    *va_arg(ap, int*) = *v;
    va_end(ap);
    return (status);
}

extern "C"
int TIFFSetField(int *v, ...)
{
    va_list ap;
    int status = 1;
    va_start(ap, v);
    *v = (int) va_arg(ap, int);
    printf("[*] *ap = %d\n", *ap);
    va_end(ap);
    return (status);
}

extern "C"
bool stack_test() {
    int *a = (int *) malloc(sizeof(int));
    int *b = (int *) malloc(sizeof(int));
    int c;
    *a = 1234;
    if (TIFFGetField(a, &c))
        TIFFSetField(b, c);
    printf("[*] Test: stack_test: b = %d\n", *b);
    return true;
}

__attribute__((weak)) extern "C" void __polytracker_save() {}

int main(int argc, char** argv) {
    std::cout << "[*] Test: current path is " << std::filesystem::current_path() << std::endl;

    char *log_file_name = getenv("POLYPATH_LOG_FILE");
    if (log_file_name) {
        printf("[*] Test: POLYPATH_LOG_FILE: %s\n", log_file_name);
    } else {
        printf("[*] Test: Cannot find POLYPATH_LOG_FILE\n");
    }

    if (argc == 1) {
        std::cout << "[!] Usage: " << argv[0] << " TEST_FILE" << std::endl;
        return 0;
    }

    open_file(argv[1]);

    char magic[4];
    assert(load_magic(argv[1], magic));
    assert(stack_taint_test(magic));
    assert(heap_taint_test(magic));
    assert(heap_taint_test2());
    assert(class_taint_test());
    assert(struct_test());
    assert(memcpy_test());
    assert(dominator_test());
    assert(stack_test());

    __polytracker_save();
    abort(); // Test if __polytracker_save is called
}