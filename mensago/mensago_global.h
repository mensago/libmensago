#ifndef MENSAGO_GLOBAL_H
#define MENSAGO_GLOBAL_H

#include <QtCore/qglobal.h>

#if defined(MENSAGO_LIBRARY)
#  define MENSAGO_EXPORT Q_DECL_EXPORT
#else
#  define MENSAGO_EXPORT Q_DECL_IMPORT
#endif

#endif // MENSAGO_GLOBAL_H
