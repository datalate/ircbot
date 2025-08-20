#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

int open_db(const char filename[]);
void close_db();

void get_deck(const char hostname[], char *deck);
void save_deck(const char hostname[], const char deck[]);

#endif
