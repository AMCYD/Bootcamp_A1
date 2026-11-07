/* Copyright (c) 2026 Amer Aboabdl — A log file parser in C language. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#define MAX_LINE_LEN 4096

// Pre-defined security keywords (all lowercase for case-insensitive matching)
const char *Suspicious_Terms[] = {
    "failed login",
    "unauthorized",
    "token changed",
    "mimikatz",
    "powershell.exe -enc",
    "access denied",
    "privilege escalation",
    "deadlock",
    "sql injection",
    "attack",
    "malware",
    "backdoor",
    "segfault",
    "buffer overflow",
    "kernel panic",
    "exception",
    "fatal",
    NULL // Sentinel
};

// Case-insensitive substring search (portable alternative to strcasestr)
// remove difference between linux and Win
const char *strcasestr_custom(const char *haystack, const char *needle) {
    if (!*needle) return haystack;
    for (; *haystack; haystack++) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            const char *h = haystack;
            const char *n = needle;
            while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
                h++;
                n++;
            }
            if (!*n) return haystack;
        }
    }
    return NULL;
}

// Strip trailing newline characters
void trim_trailing_newlines(char *str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[--len] = '\0';
    }
}


// Main
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <logfile> [optional_custom_keyword]\n", argv[0]);
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  %s auth.log\n", argv[0]);
        // fprintf(stderr, "  %s /var/log/auth.log\n", argv[0]);
        // fprintf(stderr, "  %s app.log \"critical error\"\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *filepath = argv[1];
    const char *custom_keyword = (argc >= 3) ? argv[2] : NULL;   // custom keyword

    // Open File in read mode
    FILE *file = fopen(filepath, "r");
    if (!file) {
        perror("[-] Failed to open target file");
        return EXIT_FAILURE;
    }

    // Buffer defined for line
    char buffer[MAX_LINE_LEN];
    unsigned long line_num = 0;
    unsigned long alert_count = 0;

    printf("[*] Scanning file: %s\n", filepath);
    if (custom_keyword) {
        printf("[*] Single-term mode: scanning for keyword '%s'\n", custom_keyword);
    } else {
        printf("[*] Multi-term mode: scanning for built-in security threat terms\n");
    }
    printf("======================================================================\n");

    // Read Line by line
    while (fgets(buffer, sizeof(buffer), file)) {
        line_num++;
        trim_trailing_newlines(buffer);

        // Ignore empty lines
        if (buffer[0] == '\0') continue;

        bool is_suspicious = false;
        char matched_keyword[128] = {0};

        if (custom_keyword) {
            // Check custom keyword 
            if (strcasestr_custom(buffer, custom_keyword) != NULL) {
                is_suspicious = true;
                strncpy(matched_keyword, custom_keyword, sizeof(matched_keyword) - 1);   // prevent string overflow
            }
        } else {
            // Check against default keywords list
            for (int i = 0; Suspicious_Terms[i] != NULL; i++) {
                if (strcasestr_custom(buffer, Suspicious_Terms[i]) != NULL) {
                    is_suspicious = true;
                    strncpy(matched_keyword, Suspicious_Terms[i], sizeof(matched_keyword) - 1);
                    break;
                }
            }
        }

        // Trigger Alert and increase count  - checking the susp keyword
        if (is_suspicious) {
            alert_count++;
            printf("-------------------------------------------------------\n");
            printf("ALERT: %lu \nLine: %lu \nMatched Keyword: '%s'\n", alert_count, line_num, matched_keyword);
            printf("Log Entry: %s\n\n", buffer);
        }
    }
    fclose(file);
    
    // summary
    printf("======================================================================\n");
    printf("[*] Scan complete.\n");
    printf("    Lines scanned : %lu\n", line_num);
    printf("    Total alerts  : %lu\n", alert_count);

    return (alert_count > 0) ? 2 : EXIT_SUCCESS;   // this for if you wanna automate the scipt (powershell, Bash)
}