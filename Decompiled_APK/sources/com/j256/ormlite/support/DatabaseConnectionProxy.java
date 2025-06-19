package com.j256.ormlite.support;

import android.content.res.TypedArray;
import android.media.MediaDrm;
import android.media.MediaMetadataRetriever;
import com.j256.ormlite.dao.ObjectCache;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.stmt.GenericRowMapper;
import com.j256.ormlite.stmt.StatementBuilder;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public class DatabaseConnectionProxy implements DatabaseConnection {
    private final DatabaseConnection proxy;

    public DatabaseConnectionProxy(DatabaseConnection databaseConnection) {
        this.proxy = databaseConnection;
    }

    @Override // java.lang.AutoCloseable
    public void close() throws Exception {
        boolean zIsTerminated;
        AutoCloseable autoCloseable = this.proxy;
        if (autoCloseable != null) {
            if (autoCloseable instanceof AutoCloseable) {
                autoCloseable.close();
                return;
            }
            if (!(autoCloseable instanceof ExecutorService)) {
                if (autoCloseable instanceof TypedArray) {
                    ((TypedArray) autoCloseable).recycle();
                    return;
                } else if (autoCloseable instanceof MediaMetadataRetriever) {
                    ((MediaMetadataRetriever) autoCloseable).release();
                    return;
                } else {
                    if (!(autoCloseable instanceof MediaDrm)) {
                        throw new IllegalArgumentException();
                    }
                    ((MediaDrm) autoCloseable).release();
                    return;
                }
            }
            ExecutorService executorService = (ExecutorService) autoCloseable;
            if (executorService == ForkJoinPool.commonPool() || (zIsTerminated = executorService.isTerminated())) {
                return;
            }
            executorService.shutdown();
            boolean z = false;
            while (!zIsTerminated) {
                try {
                    zIsTerminated = executorService.awaitTermination(1L, TimeUnit.DAYS);
                } catch (InterruptedException unused) {
                    if (!z) {
                        executorService.shutdownNow();
                        z = true;
                    }
                }
            }
            if (z) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public void closeQuietly() {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection != null) {
            databaseConnection.closeQuietly();
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public void commit(Savepoint savepoint) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection != null) {
            databaseConnection.commit(savepoint);
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public CompiledStatement compileStatement(String str, StatementBuilder.StatementType statementType, FieldType[] fieldTypeArr, int i, boolean z) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return null;
        }
        return databaseConnection.compileStatement(str, statementType, fieldTypeArr, i, z);
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public int delete(String str, Object[] objArr, FieldType[] fieldTypeArr) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return 0;
        }
        return databaseConnection.delete(str, objArr, fieldTypeArr);
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public int executeStatement(String str, int i) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return 0;
        }
        return databaseConnection.executeStatement(str, i);
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public Connection getUnderlyingConnection() {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return null;
        }
        return databaseConnection.getUnderlyingConnection();
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public int insert(String str, Object[] objArr, FieldType[] fieldTypeArr, GeneratedKeyHolder generatedKeyHolder) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return 0;
        }
        return databaseConnection.insert(str, objArr, fieldTypeArr, generatedKeyHolder);
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public boolean isAutoCommit() throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return false;
        }
        return databaseConnection.isAutoCommit();
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public boolean isAutoCommitSupported() throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return false;
        }
        return databaseConnection.isAutoCommitSupported();
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public boolean isClosed() throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return true;
        }
        return databaseConnection.isClosed();
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public boolean isTableExists(String str) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return false;
        }
        return databaseConnection.isTableExists(str);
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public long queryForLong(String str) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return 0L;
        }
        return databaseConnection.queryForLong(str);
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public <T> Object queryForOne(String str, Object[] objArr, FieldType[] fieldTypeArr, GenericRowMapper<T> genericRowMapper, ObjectCache objectCache) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return null;
        }
        return databaseConnection.queryForOne(str, objArr, fieldTypeArr, genericRowMapper, objectCache);
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public void releaseSavePoint(Savepoint savepoint) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection != null) {
            databaseConnection.releaseSavePoint(savepoint);
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public void rollback(Savepoint savepoint) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection != null) {
            databaseConnection.rollback(savepoint);
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public void setAutoCommit(boolean z) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection != null) {
            databaseConnection.setAutoCommit(z);
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public Savepoint setSavePoint(String str) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return null;
        }
        return databaseConnection.setSavePoint(str);
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public int update(String str, Object[] objArr, FieldType[] fieldTypeArr) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return 0;
        }
        return databaseConnection.update(str, objArr, fieldTypeArr);
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public long queryForLong(String str, Object[] objArr, FieldType[] fieldTypeArr) throws SQLException {
        DatabaseConnection databaseConnection = this.proxy;
        if (databaseConnection == null) {
            return 0L;
        }
        return databaseConnection.queryForLong(str, objArr, fieldTypeArr);
    }
}
