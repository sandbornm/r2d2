/**
 * structs.c - Structure and pointer examples for ARM reverse engineering
 *
 * Demonstrates:
 * - Memory layout of structures
 * - Pointer arithmetic
 * - Array indexing (LDR with scaled offset)
 * - Linked list traversal
 * - Function pointers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple structure with padding */
typedef struct {
    char name[32];
    int age;
    float salary;
} Employee;

/* Linked list node */
typedef struct Node {
    int data;
    struct Node *next;
} Node;

/* Structure with function pointer (vtable-like) */
typedef struct {
    int value;
    int (*operation)(int, int);
    const char *name;
} Calculator;

/* Operations for function pointer demo */
int add(int a, int b) { return a + b; }
int subtract(int a, int b) { return a - b; }
int multiply(int a, int b) { return a * b; }

/* Create a new linked list node */
Node* create_node(int data) {
    Node *node = (Node*)malloc(sizeof(Node));
    if (node) {
        node->data = data;
        node->next = NULL;
    }
    return node;
}

/* Sum all elements in linked list - shows pointer chasing */
int sum_list(Node *head) {
    int sum = 0;
    while (head != NULL) {
        sum += head->data;
        head = head->next;
    }
    return sum;
}

/* Free linked list */
void free_list(Node *head) {
    while (head != NULL) {
        Node *next = head->next;
        free(head);
        head = next;
    }
}

int main(void) {
    /* Structure demo */
    printf("=== Structure Demo ===\n");
    Employee emp = {"Alice", 30, 75000.0f};
    printf("Employee: %s, Age: %d, Salary: %.2f\n",
           emp.name, emp.age, emp.salary);
    printf("sizeof(Employee) = %zu\n", sizeof(Employee));
    printf("Offsets: name=%zu, age=%zu, salary=%zu\n",
           (size_t)&((Employee*)0)->name,
           (size_t)&((Employee*)0)->age,
           (size_t)&((Employee*)0)->salary);

    /* Array of structures */
    printf("\n=== Array Demo ===\n");
    int numbers[] = {10, 20, 30, 40, 50};
    int sum = 0;
    for (int i = 0; i < 5; i++) {
        sum += numbers[i];
    }
    printf("Sum of array: %d\n", sum);

    /* Linked list demo */
    printf("\n=== Linked List Demo ===\n");
    Node *head = create_node(1);
    head->next = create_node(2);
    head->next->next = create_node(3);
    head->next->next->next = create_node(4);

    printf("List sum: %d\n", sum_list(head));
    free_list(head);

    /* Function pointer demo */
    printf("\n=== Function Pointer Demo ===\n");
    Calculator calcs[] = {
        {10, add, "add"},
        {20, subtract, "subtract"},
        {5, multiply, "multiply"},
    };

    for (int i = 0; i < 3; i++) {
        int result = calcs[i].operation(calcs[i].value, 3);
        printf("%s(%d, 3) = %d\n", calcs[i].name, calcs[i].value, result);
    }

    return 0;
}
