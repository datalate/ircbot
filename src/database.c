#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#include "database.h"

static sqlite3 *db;

int open_db(const char filename[]) {
    close_db();

    printf("Opening sqlite3 database '%s'\n", filename);

    if (sqlite3_open(filename, &db) != SQLITE_OK) {
        fprintf(stderr, "Failed to open database: %s\n", sqlite3_errmsg(db));
        close_db();

        return 1;
    }

    return 0;
}

void close_db() {
    if (db != NULL) {
        sqlite3_close(db);
        db = NULL;
    }
}

void get_deck(const char hostname[], char* deck) {
    if (!db) return;

    static const char *query = "SELECT Deck FROM PokerDeck WHERE Hostname=?";
    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite3_prepare_v2() failed: %s\n", sqlite3_errmsg(db));
        return;
    }
    
    if (sqlite3_bind_text(stmt, 1, hostname, -1, SQLITE_STATIC) != SQLITE_OK) {
        fprintf(stderr, "sqlite3_bind_text() failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }
    
    if ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char *saved_deck = sqlite3_column_text(stmt, 0);
        strcpy(deck, (const char*)saved_deck); // check cast
    }

    sqlite3_finalize(stmt);

    if (strlen(deck) > 0) {
        static const char *deleteQuery = "DELETE FROM PokerDeck WHERE Hostname=?";

        rc = sqlite3_prepare_v2(db, deleteQuery, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "sqlite3_prepare_v2() failed: %s\n", sqlite3_errmsg(db));
            return;
        }
        
        if (sqlite3_bind_text(stmt, 1, hostname, -1, SQLITE_STATIC) != SQLITE_OK) {
            fprintf(stderr, "sqlite3_bind_text() failed: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return;
        }

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            fprintf(stderr, "sqlite3_step() failed: %s\n", sqlite3_errmsg(db));
        }

        sqlite3_finalize(stmt);
    }
}

void save_deck(const char hostname[], const char deck[]) {
    if (!db) return;

    static const char *query = "INSERT INTO PokerDeck (Hostname, Deck) VALUES (?, ?) ON CONFLICT (Hostname) DO UPDATE SET Deck=EXCLUDED.Deck";
    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite3_prepare_v2() failed: %s\n", sqlite3_errmsg(db));
        return;
    }

    if (sqlite3_bind_text(stmt, 1, hostname, -1, SQLITE_STATIC) != SQLITE_OK) {
        fprintf(stderr, "sqlite3_bind_text() failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    if (sqlite3_bind_text(stmt, 2, deck, -1, SQLITE_STATIC) != SQLITE_OK) {
        fprintf(stderr, "sqlite3_bind_text() failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "sqlite3_step() failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    sqlite3_finalize(stmt);
}

