package com.j256.ormlite.android;

import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.db.SqliteAndroidDatabaseType;
import com.j256.ormlite.logger.Logger;
import com.j256.ormlite.logger.LoggerFactory;
import com.j256.ormlite.support.BaseConnectionSource;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.support.DatabaseConnection;
import com.j256.ormlite.support.DatabaseConnectionProxyFactory;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public class AndroidConnectionSource extends BaseConnectionSource implements ConnectionSource {
    private static DatabaseConnectionProxyFactory connectionProxyFactory;
    private static final Logger logger = LoggerFactory.getLogger((Class<?>) AndroidConnectionSource.class);
    private boolean cancelQueriesEnabled;
    private DatabaseConnection connection;
    private final DatabaseType databaseType;
    private final SQLiteOpenHelper helper;
    private volatile boolean isOpen;
    private final SQLiteDatabase sqliteDatabase;

    public AndroidConnectionSource(SQLiteOpenHelper sQLiteOpenHelper) {
        this.connection = null;
        this.isOpen = true;
        this.databaseType = new SqliteAndroidDatabaseType();
        this.cancelQueriesEnabled = false;
        this.helper = sQLiteOpenHelper;
        this.sqliteDatabase = null;
    }

    public static void setDatabaseConnectionProxyFactory(DatabaseConnectionProxyFactory databaseConnectionProxyFactory) {
        connectionProxyFactory = databaseConnectionProxyFactory;
    }

    @Override // com.j256.ormlite.support.BaseConnectionSource, com.j256.ormlite.support.ConnectionSource
    public void clearSpecialConnection(DatabaseConnection databaseConnection) {
        clearSpecial(databaseConnection, logger);
    }

    @Override // java.lang.AutoCloseable
    public void close() {
        this.isOpen = false;
    }

    @Override // com.j256.ormlite.support.BaseConnectionSource, com.j256.ormlite.support.ConnectionSource
    public void closeQuietly() {
        close();
    }

    @Override // com.j256.ormlite.support.BaseConnectionSource, com.j256.ormlite.support.ConnectionSource
    public DatabaseType getDatabaseType() {
        return this.databaseType;
    }

    @Override // com.j256.ormlite.support.BaseConnectionSource, com.j256.ormlite.support.ConnectionSource
    public DatabaseConnection getReadOnlyConnection(String str) throws SQLException {
        return getReadWriteConnection(str);
    }

    @Override // com.j256.ormlite.support.BaseConnectionSource, com.j256.ormlite.support.ConnectionSource
    public DatabaseConnection getReadWriteConnection(String str) throws SQLException {
        DatabaseConnection savedConnection = getSavedConnection();
        if (savedConnection != null) {
            return savedConnection;
        }
        DatabaseConnection databaseConnection = this.connection;
        if (databaseConnection == null) {
            SQLiteDatabase writableDatabase = this.sqliteDatabase;
            if (writableDatabase == null) {
                try {
                    writableDatabase = this.helper.getWritableDatabase();
                } catch (android.database.SQLException e) {
                    throw new SQLException("Getting a writable database from helper " + this.helper + " failed", e);
                }
            }
            AndroidDatabaseConnection androidDatabaseConnection = new AndroidDatabaseConnection(writableDatabase, true, this.cancelQueriesEnabled);
            this.connection = androidDatabaseConnection;
            DatabaseConnectionProxyFactory databaseConnectionProxyFactory = connectionProxyFactory;
            if (databaseConnectionProxyFactory != null) {
                this.connection = databaseConnectionProxyFactory.createProxy(androidDatabaseConnection);
            }
            logger.trace("created connection {} for db {}, helper {}", this.connection, writableDatabase, this.helper);
        } else {
            logger.trace("{}: returning read-write connection {}, helper {}", this, databaseConnection, this.helper);
        }
        return this.connection;
    }

    public boolean isCancelQueriesEnabled() {
        return this.cancelQueriesEnabled;
    }

    @Override // com.j256.ormlite.support.BaseConnectionSource, com.j256.ormlite.support.ConnectionSource
    public boolean isOpen(String str) {
        return this.isOpen;
    }

    @Override // com.j256.ormlite.support.BaseConnectionSource, com.j256.ormlite.support.ConnectionSource
    public boolean isSingleConnection(String str) {
        return true;
    }

    @Override // com.j256.ormlite.support.BaseConnectionSource, com.j256.ormlite.support.ConnectionSource
    public void releaseConnection(DatabaseConnection databaseConnection) {
    }

    @Override // com.j256.ormlite.support.BaseConnectionSource, com.j256.ormlite.support.ConnectionSource
    public boolean saveSpecialConnection(DatabaseConnection databaseConnection) throws SQLException {
        return saveSpecial(databaseConnection);
    }

    public void setCancelQueriesEnabled(boolean z) {
        this.cancelQueriesEnabled = z;
    }

    public String toString() {
        return getClass().getSimpleName() + "@" + Integer.toHexString(super.hashCode());
    }

    public AndroidConnectionSource(SQLiteDatabase sQLiteDatabase) {
        this.connection = null;
        this.isOpen = true;
        this.databaseType = new SqliteAndroidDatabaseType();
        this.cancelQueriesEnabled = false;
        this.helper = null;
        this.sqliteDatabase = sQLiteDatabase;
    }
}
