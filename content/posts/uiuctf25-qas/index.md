---
# example: UIUCTF 25 - ELF Capsule
title: UIUCTF 25 - QAS

# date of publication/creation
date: '2025-07-28T11:21:17+02:00'

# add link to your original blog post
upstream: ""

# set to true to use mathjax
math: false

# for ctf writeups add the category for the ctf event
# --> name of ctf + short year (example uiuctf25)
categories:
- writeup
- uiuctf25
tags:
- pwn
- bruteforce
- easy
authors:
- nect
---

The challenge computes the hash of an integer we provide and
prints the flag if the hashed output matches a constant.

The code is very straightforward and the only annoyance
is the usage of confusing type names for integer types.

Here's the code stripped from comments:

```c
typedef int not_int_small;
typedef short int_small;
typedef int not_int_big;
typedef not_int_small int_big;
typedef unsigned char quantum_byte;
typedef quantum_byte* quantum_ptr;

typedef struct {
    not_int_big val;
} PASSWORD_QUANTUM;

typedef struct {
    int_small val;
    quantum_byte padding[2];
    quantum_byte checksum;
    quantum_byte reserved;
} INPUT_QUANTUM;

typedef struct quantum_data_s quantum_data_t;
struct __attribute__((packed)) quantum_data_s {
    INPUT_QUANTUM input;
    PASSWORD_QUANTUM password;
    quantum_byte entropy_pool[8];
    quantum_byte quantum_state[16];
};

static inline quantum_byte generate_quantum_entropy() {
    static quantum_byte seed = 0x42;
    seed = ((seed << 3) ^ (seed >> 5)) + 0x7f;
    return seed;
}

void init_quantum_security(quantum_data_t* qdata) {
    for (int i = 0; i < 8; i++) {
        qdata->entropy_pool[i] = generate_quantum_entropy();
    }
    for (int i = 0; i < 16; i++) {
        qdata->quantum_state[i] = (quantum_byte)(i * 0x11 + 0x33);
    }

    qdata->input.padding[0] = 0;
    qdata->input.padding[1] = 0;
}

not_int_big quantum_hash(INPUT_QUANTUM input, quantum_byte* entropy) {
    int_small input_val = input.val;
    not_int_big hash = input_val;

    hash ^= (entropy[0] << 8) | entropy[1];
    hash ^= (entropy[2] << 4) | (entropy[3] >> 4);
    hash += (entropy[4] * entropy[5]) & 0xff;
    hash ^= entropy[6] ^ entropy[7];
    hash |= 0xeee;
    hash ^= input.padding[0] << 8 | input.padding[1];
    return hash;
}

void access_granted() {
    printf("Quantum authentication successful!\n");
    printf("Accessing secured vault...\n");

    FILE *fp = fopen("flag.txt", "r");
    if (fp == NULL) {
        printf("Error: Quantum vault is offline\n");
        printf("Please contact the quantum administrator.\n");
        return;
    }

    char flag[100];
    if (fgets(flag, sizeof(flag), fp) != NULL) {
        printf("CLASSIFIED FLAG: %s\n", flag);
    } else {
        printf("Error: Quantum decryption failed\n");
        printf("Please contact the quantum administrator.\n");
    }
    fclose(fp);
}

int main() {
    quantum_data_t qdata;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    init_quantum_security(&qdata);
    qdata.password.val = 0x555;

    printf("=== QUANTUM AUTHENTICATION SYSTEM v2.7.3 ===\n");
    printf("Initializing quantum security protocols...\n");

    for (volatile int i = 0; i < 100000; i++) { }

    printf("Quantum entropy generated. System ready.\n");
    printf("Please enter your quantum authentication code: ");

    // qdata.input.val is a short !!!
    if (scanf("%d", (int*)&qdata.input.val) != 1) {
        printf("Invalid quantum input format!\n");
        return 1;
    }

    qdata.input.checksum = (quantum_byte)(qdata.input.val & 0xff);
    not_int_big hashed_input = quantum_hash(qdata.input, qdata.entropy_pool);

    printf("Quantum hash computed: 0x%x\n", hashed_input);
    if (hashed_input == qdata.password.val) {
        access_granted();
    } else {
        printf("Quantum authentication failed!\n");
        printf("Access denied. Incident logged.\n");
    }
    return 0;
}
```

Since the constant is known (`0x555`) and the domain of the input is small (32-bit),
we can just bruteforce it!

Valid solutions can be found by changing the main function like so:

```c
int main() {
    quantum_data_t qdata;
    qdata.password.val = 0x555;

    for (int i = INT_MIN; i < INT_MAX; i++) {
        seed = 0x42;
		init_quantum_security(&qdata);

		memcpy(&qdata.input.val, &i, sizeof(int));
		qdata.input.checksum = (quantum_byte)(qdata.input.val & 0xff);
		int hashed_input = quantum_hash(qdata.input, qdata.entropy_pool);

		if (hashed_input == qdata.password.val) {
			printf("Found %d\n", i);
		}
    }
	printf("Done\n");
}
```

In a few seconds we find a lot of negative numbers (32560 to be exact) that match our expected hash!

```
...
Found -1141148752
Found -1141148750
Found -1141148748
Found -1141148746
Found -1141148744
...
```

Now we can profit:

```bash
$ ncat --ssl qas.chal.uiuc.tf 1337
== proof-of-work: disabled ==
=== QUANTUM AUTHENTICATION SYSTEM v2.7.3 ===
Initializing quantum security protocols...
Quantum entropy generated. System ready.
Please enter your quantum authentication code: -1141148674
Quantum hash computed: 0x555
Quantum authentication successful!
Accessing secured vault...
CLASSIFIED FLAG: uiuctf{qu4ntum_0v3rfl0w_2d5ad975653b8f29}
```

With the cheesy solution out of the way, what is the vuln here?

`scanf("%d", (int*)&qdata.input.val)` reads 4 bytes into the input struct. But the `val` field is a short!
Since the struct is packed, this means that we are overwriting the following field, which in this case is a `char[2]` called `padding`.

Contrary to common sense, this field is actually used in the hash function: `hash ^= input.padding[0] << 8 | input.padding[1];`

By providing certain negative numbers we can obtain the right output value and win.
Also note that there are no positive solutions.

