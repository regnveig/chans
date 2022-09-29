#include "uuid.h"

// result should be deleted via gcry_free()
void generate_uuid(char** uuid) {
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    *uuid = gcry_malloc_secure(UUID_STR_LEN);
    uuid_unparse_lower(binuuid, *uuid);
}
