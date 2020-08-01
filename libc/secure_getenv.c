// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdlib.h>

char* secure_getenv(const char* name)
{
    return getenv(name);
}
