/* Render an analysis Report as human text and as machine-readable JSON. */
#ifndef LEAKSCOPE_REPORT_H
#define LEAKSCOPE_REPORT_H

#include <stdio.h>

#include "analyze.h"
#include "elfload.h"

const char *kind_title(const char *kind);
void report_write_text(FILE *f, const Report *r, const LoadedBinary *bin);
void report_write_json(FILE *f, const Report *r, const LoadedBinary *bin);

#endif
