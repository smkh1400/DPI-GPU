#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define ALPHABET_SIZE 52

int charToIndex(char c) {
    if (c >= 'a' && c <= 'z') {
        return c - 'a';
    } else if (c >= 'A' && c <= 'Z') {
        return c - 'A' + 26; 
    }
    return -1;
}

typedef struct TrieNode {
    struct TrieNode *children[ALPHABET_SIZE];
    bool isEndOfWord;
} TrieNode;

TrieNode *createNode() {
    TrieNode *node = (TrieNode *)malloc(sizeof(TrieNode));
    node->isEndOfWord = false;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        node->children[i] = NULL;
    }
    return node;
}

void insert(TrieNode *root, const char *pattern, size_t length) {
    TrieNode *current = root;
    for (int i = 0; i < length; i++) {
        int index = charToIndex(pattern[i]);
        if (index == -1) {
            continue;
        }
        if (!current->children[index]) {
            current->children[index] = createNode();
        }
        current = current->children[index];
    }
    current->isEndOfWord = true;
}

bool searchInText(TrieNode *root, const char *text, size_t length) {
    for (int i = 0; i < length; i++) {
        TrieNode *current = root;
        for (int j = i; j < length; j++) {
            int index = charToIndex(text[j]);
            if (index == -1 || !current->children[index]) {
                break;
            }
            current = current->children[index];
            if (current->isEndOfWord) {
                return true;
            }
        }
    }
    return false;
}

int main() {
    char text[] = "ThisIsATestText";
    char pattern[] = "Text";

    TrieNode *root = createNode();

    insert(root, pattern, sizeof(pattern));

    if (searchInText(root, text, sizeof(text))) {
        printf("Pattern found in the text.\n");
    } else {
        printf("Pattern not found in the text.\n");
    }

    return 0;
}
