/* Command-line entry point for LeakScope.
 *
 *   leakscope MANIFEST.json [--json OUT.json] [--quiet] [--extra N]
 *
 * Exit code is 0 when the target is reported SAFE and 1 when a leak is found,
 * so LeakScope can be used as a pass/fail gate in CI.  Usage and input errors
 * exit with 2. */
#ifndef LEAKSCOPE_CLI_H
#define LEAKSCOPE_CLI_H

int leakscope_main(int argc, char **argv);

#endif
