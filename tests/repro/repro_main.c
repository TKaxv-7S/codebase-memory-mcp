/*
 * repro_main.c — Entry point for the cumulative BUG-REPRODUCTION suite.
 *
 * This runner is SEPARATE from the gating `make test` (test-runner). It exists
 * to hold reproduce-first cases for every OPEN bug issue. Each case asserts the
 * CORRECT behaviour, so it is **RED until the bug is fixed** — the redness is the
 * deliverable (proof the bug is real + the permanent regression guard).
 *
 * Because these cases are red by design, they MUST NOT live in `ALL_TEST_SRCS`
 * (that would turn the PR gate `ci-ok` red and wedge every merge). They are built
 * + run only via `make test-repro` and the `bug-repro.yml` workflow, neither of
 * which gates branch protection.
 *
 * Exit status: non-zero when any reproduction is still RED (the expected state).
 * The `bug-repro.yml` workflow treats that as the status board, not a hard fail.
 *
 * Adding a cluster:
 *   1. create tests/repro/repro_<cluster>.c exporting `void suite_repro_<cluster>(void)`
 *   2. add it to TEST_REPRO_SRCS in Makefile.cbm
 *   3. forward-declare + RUN_SUITE it below
 */

/* Global test counters (declared extern in test_framework.h) */
int tf_pass_count = 0;
int tf_fail_count = 0;
int tf_skip_count = 0;

#include "test_framework.h"

/* ── Repro suites (one per bug cluster / issue) ─────────────────── */
extern void suite_repro_extraction(void);
extern void suite_repro_issue495(void);
extern void suite_repro_issue521(void);
extern void suite_repro_issue382(void);

int main(void) {
    /* Unbuffered: a reproduction may crash/_exit (or a sanitizer may _exit on a
     * leak) before stdio flushes — keep every printed line so the summary and the
     * RED rows always reach the board even on an abnormal exit. */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("  CUMULATIVE BUG-REPRODUCTION SUITE\n");
    printf("  RED rows are EXPECTED — each is an open bug reproduced.\n");
    printf("  A row that PASSES means that bug appears FIXED → flip it\n");
    printf("  into the gating suite and close the issue with the guard.\n");
    printf("════════════════════════════════════════════════════════════\n");

    RUN_SUITE(repro_extraction);
    RUN_SUITE(repro_issue495);
    RUN_SUITE(repro_issue521);
    RUN_SUITE(repro_issue382);

    TEST_SUMMARY();
}
