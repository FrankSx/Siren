/*
 * SIREN v3.0 - CVE-2026-32836 vulnerable-target harness
 * frankSx, 2026-09-23
 *
 * Simulates a real TTS/audio preprocessing service: it opens an untrusted
 * FLAC upload WITH a metadata callback (the exact pattern used by thumbnail
 * extractors, cover-art scrapers, and multimodal ingest pipelines), which is
 * the gate condition that makes drflac__read_and_decode_metadata() parse the
 * PICTURE body and hit the unchecked allocation at dr_flac.h:6750.
 *
 * Build against dr_libs <= 0.13.3 (vulnerable) and then against
 * fefced4/4f5a4cd/663239a (patched) to observe the differential:
 *
 *   clang -fsanitize=address -O1 -g -o siren_harness siren_v3_harness.c
 *   ./siren_harness siren_v3_cve-2026-32836_minimal_78B.flac
 *
 * Vulnerable:  malloc(4294967295) from dr_flac.h:6750 -> ASan abort / OOM kill
 * Patched:     bounds check first -> drflac_open_*_with_metadata returns NULL
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#if defined(__SANITIZE_ADDRESS__) || \
    (defined(__has_feature) && __has_feature(address_sanitizer))
#include <sanitizer/common_interface_defs.h>
/* Abort loudly on the giant allocation so the origin stack is printed */
void __sanitizer_malloc_hook(void *ptr, size_t size)
{
    (void)ptr;
    if (size < 512UL * 1024 * 1024) return;
    fprintf(stderr, "[harness] oversized allocation: %zu bytes\n", size);
    __sanitizer_print_stack_trace();
    abort();
}
#endif

#define DR_FLAC_IMPLEMENTATION
#include "dr_flac.h"   /* <= 0.13.3 = vulnerable; fefced4+ = patched */

static void on_meta(void *udata, drflac_metadata *m)
{
    (void)udata;
    printf("  [on_meta] block type=%u size=%u\n", m->type, m->rawDataSize);
    if (m->type == DRFLAC_METADATA_BLOCK_TYPE_PICTURE)
        printf("  [on_meta] PICTURE mimeLength=%u descriptionLength=%u\n",
               m->data.picture.mimeLength, m->data.picture.descriptionLength);
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <file.flac>\n", argv[0]); return 1; }

    printf("SIREN v3.0 harness - CVE-2026-32836 target simulation\n");
    printf("Opening '%s' with metadata callback (cover-art ingest path)...\n", argv[1]);

    /* The vulnerable entry point: any drflac_open_*_with_metadata() variant
     * with a non-NULL onMeta. drflac_open_file() without callback is NOT
     * affected - the PICTURE body is skipped when onMeta == NULL. */
    drflac *p = drflac_open_file_with_metadata(argv[1], on_meta, NULL, NULL);

    printf("Result: %s\n", p ? "opened (file parsed)" : "NULL (rejected)");
    if (p) drflac_close(p);
    return 0;
}
