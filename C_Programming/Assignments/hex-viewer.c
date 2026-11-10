/*
* Project: A Hexa Viewer in C language
* Author:  AMER
*/
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#define HEADER_BYTES 16   // defin the size of bytes to read

// Structure to hold signature patterns
typedef struct {
    const char *name;
    const unsigned char magic[8];
    size_t length;
} FileSignature;

// Common file signatures (magic bytes)
static const FileSignature KNOWN_SIGNATURES[] = {
    {"Windows PE (EXE/DLL)",{0x4D, 0x5A},                                    2}, // MZ
    {"PNG Image",          {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 8},
    {"JPEG Image",         {0xFF, 0xD8, 0xFF},                               3},
    {"GIF Image (87a/89a)",{0x47, 0x49, 0x46, 0x38},                         4},
    {"PDF Document",       {0x25, 0x50, 0x44, 0x46},                         4}, // %PDF
    {"ZIP / DOCX / JAR",   {0x50, 0x4B, 0x03, 0x04},                         4}, // PK..
    {"ELF Executable",     {0x7F, 0x45, 0x4C, 0x46},                         4}, // .ELF  
    {"Java Class File",    {0xCA, 0xFE, 0xBA, 0xBE},                         4},
    {"GZIP Archive",       {0x1F, 0x8B},                                     2},
    {"SQLite 3 Database",  {0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66}, 8}  // SQLite f
};

void inspect_magic( char *filename) {
    FILE *fp = fopen(filename, "rb");    // open file and read binary mode
    if (!fp) {
        perror("Error opening file");
        return;
    }

    unsigned char header[HEADER_BYTES] = {0};
    size_t bytes_read = fread(header, 1, HEADER_BYTES, fp);
    fclose(fp); // close file

    if (bytes_read == 0) {
        printf("File is empty: %s\n", filename);
        return;
    }

    printf("File: %s\n", filename);
    printf("Read: %zu bytes\n\n", bytes_read);

    // 1. Hex print using %02X
    printf("Hex:    ");
    for (size_t i = 0; i < bytes_read; i++) {
        printf("%02X ", header[i]);
    }
    printf("\n");

    // 2. ASCII 
    printf("ASCII:");
    for (size_t i = 0; i < bytes_read; i++) {
        printf(" %c ", isprint(header[i]) ? header[i] : '.');
    }
    printf("\n\n");

    // 3. Match against known signatures
    const char *detected = "Unknown signature";
    size_t count = sizeof(KNOWN_SIGNATURES) / sizeof(KNOWN_SIGNATURES[0]);

    for (size_t i = 0; i < count; i++) {
        if (bytes_read >= KNOWN_SIGNATURES[i].length &&
            memcmp(header, KNOWN_SIGNATURES[i].magic, KNOWN_SIGNATURES[i].length) == 0) {
            detected = KNOWN_SIGNATURES[i].name;
            break;
        }
    }
    printf("Identified As: %s\n", detected);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    inspect_magic(argv[1]);
    return 0;
}
