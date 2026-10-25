#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>


int main() {
    
    char password[20];      
    
    // we need to check either the conditions True or False, we use boolean
   
    bool has_upper = false;
    bool has_lower = false;
    bool has_number = false;
    bool has_symbols = false;

    // read input from user using fgets
    printf("Enter your password: ");
    fgets(password, sizeof(password), stdin);  // fgets(variable_to_store_the_value, max_input_length, input_type);
    
    // 4. Traverse the array slot-by-slot
    for (int i = 0; password[i] != '\0'; i++) {
        
        char ch = password[i];

        if (isupper(ch)) {
            has_upper = true; // capital letter
        }
        if (islower(ch)) {
            has_lower = true; // small letter
        }
        if (isdigit(ch)) {
            has_number = true; // number
        }
        if (ispunct(ch)){       // symbol (#,$)
            has_symbols = true;
        }
        
    }
    // decision logic
    int pass_length = strlen(password);   // count number char of password
    
    if (pass_length < 8) {
        printf("Fail: Password must be at least 8 characters long.\n");
    } else if (has_upper && has_lower && has_number && has_symbols) {
        printf("Success: Your password is Strong\n");
    } else {
        printf("Fail: Password must include (Capital and small letters, numbers, and Symbols)\n");
    }

    return 0;
}