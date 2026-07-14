/* reportnative — a small CPython C extension backing the reportkit toolkit's
   native cell-packing helper. Built as an importable module (setup.py) and,
   for sanitizer coverage, compiled into a standalone driver (reportnative_harness.c). */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "reportnative_core.h"

static PyObject *reportnative_pack_cells(PyObject *self, PyObject *args) {
    unsigned int rows, width;
    unsigned char fill;
    if (!PyArg_ParseTuple(args, "IIb", &rows, &width, &fill)) {
        return NULL;
    }
    return PyLong_FromSize_t(pack_cells(rows, width, fill));
}

static PyMethodDef reportnative_methods[] = {
    {"pack_cells", reportnative_pack_cells, METH_VARARGS,
     "Pack a rows x width grid of report cells and return the packed-cell checksum."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef reportnative_module = {
    PyModuleDef_HEAD_INIT, "reportnative",
    "Native helpers for the reportkit report toolkit.", -1, reportnative_methods,
};

PyMODINIT_FUNC PyInit_reportnative(void) {
    return PyModule_Create(&reportnative_module);
}
