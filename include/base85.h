#ifndef BASE85_H
#define BASE85_H

#include<QByteArray>
#include<QString>

void base85encode(const QByteArray &ba, QString &out);
bool base85decode(const QString &s, QByteArray &out);

#endif // BASE85_H
