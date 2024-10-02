int default_key = 9;
std::string EncryptDecrypt(std::string input, int key) {
    std::string output = input;
    char a;
    key = rand() % 99;
    for(size_t i = 0; i < input.length(); ++i) {
        a = input[i];
        int b = static_cast<int>(a);
        b ^= key;
        a = static_cast<char>(b);
        output[i] = a;
    }
    return output;
}