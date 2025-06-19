package com.j256.ormlite.android;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteStatement;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.j256.ormlite.dao.ObjectCache;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.field.SqlType;
import com.j256.ormlite.logger.Logger;
import com.j256.ormlite.logger.LoggerFactory;
import com.j256.ormlite.misc.IOUtils;
import com.j256.ormlite.stmt.GenericRowMapper;
import com.j256.ormlite.stmt.StatementBuilder;
import com.j256.ormlite.support.CompiledStatement;
import com.j256.ormlite.support.DatabaseConnection;
import com.j256.ormlite.support.GeneratedKeyHolder;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Savepoint;

/* loaded from: classes2.dex */
public class AndroidDatabaseConnection implements DatabaseConnection {
    private final boolean cancelQueriesEnabled;
    private final SQLiteDatabase db;
    private final boolean readWrite;
    private static Logger logger = LoggerFactory.getLogger((Class<?>) AndroidDatabaseConnection.class);
    private static final String[] NO_STRING_ARGS = new String[0];

    /* renamed from: com.j256.ormlite.android.AndroidDatabaseConnection$1, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$j256$ormlite$field$SqlType;

        static {
            int[] iArr = new int[SqlType.values().length];
            $SwitchMap$com$j256$ormlite$field$SqlType = iArr;
            try {
                iArr[SqlType.STRING.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.LONG_STRING.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.CHAR.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.BOOLEAN.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.BYTE.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.SHORT.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.INTEGER.ordinal()] = 7;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.LONG.ordinal()] = 8;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.FLOAT.ordinal()] = 9;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.DOUBLE.ordinal()] = 10;
            } catch (NoSuchFieldError unused10) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.BYTE_ARRAY.ordinal()] = 11;
            } catch (NoSuchFieldError unused11) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.SERIALIZABLE.ordinal()] = 12;
            } catch (NoSuchFieldError unused12) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.DATE.ordinal()] = 13;
            } catch (NoSuchFieldError unused13) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.BLOB.ordinal()] = 14;
            } catch (NoSuchFieldError unused14) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.BIG_DECIMAL.ordinal()] = 15;
            } catch (NoSuchFieldError unused15) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.UNKNOWN.ordinal()] = 16;
            } catch (NoSuchFieldError unused16) {
            }
        }
    }

    public static class OurSavePoint implements Savepoint {
        private String name;

        public OurSavePoint(String str) {
            this.name = str;
        }

        @Override // java.sql.Savepoint
        public int getSavepointId() {
            return 0;
        }

        @Override // java.sql.Savepoint
        public String getSavepointName() {
            return this.name;
        }
    }

    public AndroidDatabaseConnection(SQLiteDatabase sQLiteDatabase, boolean z) {
        this(sQLiteDatabase, z, false);
    }

    private void bindArgs(SQLiteStatement sQLiteStatement, Object[] objArr, FieldType[] fieldTypeArr) throws SQLException {
        if (objArr == null) {
            return;
        }
        for (int i = 0; i < objArr.length; i++) {
            Object obj = objArr[i];
            if (obj == null) {
                sQLiteStatement.bindNull(i + 1);
            } else {
                SqlType sqlType = fieldTypeArr[i].getSqlType();
                switch (AnonymousClass1.$SwitchMap$com$j256$ormlite$field$SqlType[sqlType.ordinal()]) {
                    case 1:
                    case 2:
                    case 3:
                        sQLiteStatement.bindString(i + 1, obj.toString());
                        break;
                    case 4:
                    case 5:
                    case 6:
                    case 7:
                    case 8:
                        sQLiteStatement.bindLong(i + 1, ((Number) obj).longValue());
                        break;
                    case 9:
                    case 10:
                        sQLiteStatement.bindDouble(i + 1, ((Number) obj).doubleValue());
                        break;
                    case 11:
                    case 12:
                        sQLiteStatement.bindBlob(i + 1, (byte[]) obj);
                        break;
                    case 13:
                    case 14:
                    case 15:
                        throw new SQLException("Invalid Android type: " + sqlType);
                    default:
                        throw new SQLException("Unknown sql argument type: " + sqlType);
                }
            }
        }
    }

    private int execute(String str, Object[] objArr, FieldType[] fieldTypeArr, String str2) throws SQLException {
        SQLiteStatement sQLiteStatementCompileStatement = null;
        try {
            try {
                sQLiteStatementCompileStatement = this.db.compileStatement(str);
                bindArgs(sQLiteStatementCompileStatement, objArr, fieldTypeArr);
                int iExecuteUpdateDelete = sQLiteStatementCompileStatement.executeUpdateDelete();
                if (iExecuteUpdateDelete < 0) {
                    iExecuteUpdateDelete = selectNumChanges(str2);
                }
                logger.trace("{} statement is compiled and executed, changed {}: {}", str2, Integer.valueOf(iExecuteUpdateDelete), str);
                return iExecuteUpdateDelete;
            } catch (android.database.SQLException e) {
                throw new SQLException("updating database failed: " + str, e);
            }
        } finally {
            closeQuietly(sQLiteStatementCompileStatement);
        }
    }

    private int selectNumChanges(String str) {
        SQLiteStatement sQLiteStatementCompileStatement = null;
        try {
            try {
                sQLiteStatementCompileStatement = this.db.compileStatement("SELECT CHANGES()");
                return (int) sQLiteStatementCompileStatement.simpleQueryForLong();
            } catch (android.database.SQLException e) {
                logger.warn(e, "{} unable to run statement 'SELECT CHANGES()' to get the changed lines", str);
                closeQuietly(sQLiteStatementCompileStatement);
                return 1;
            }
        } finally {
            closeQuietly(sQLiteStatementCompileStatement);
        }
    }

    private String[] toStrings(Object[] objArr) {
        if (objArr == null || objArr.length == 0) {
            return null;
        }
        String[] strArr = new String[objArr.length];
        for (int i = 0; i < objArr.length; i++) {
            Object obj = objArr[i];
            if (obj == null) {
                strArr[i] = null;
            } else {
                strArr[i] = obj.toString();
            }
        }
        return strArr;
    }

    @Override // java.lang.AutoCloseable
    public void close() throws Exception {
        try {
            this.db.close();
            logger.trace("{}: db {} closed", this, this.db);
        } catch (android.database.SQLException e) {
            throw new SQLException("problems closing the database connection", e);
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public void closeQuietly() {
        IOUtils.closeQuietly(this);
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public void commit(Savepoint savepoint) throws SQLException {
        try {
            this.db.setTransactionSuccessful();
            this.db.endTransaction();
            if (savepoint == null) {
                logger.trace("{}: transaction is successfully ended", this);
            } else {
                logger.trace("{}: transaction {} is successfully ended", this, savepoint.getSavepointName());
            }
        } catch (android.database.SQLException e) {
            if (savepoint == null) {
                throw new SQLException("problems committing transaction", e);
            }
            throw new SQLException("problems committing transaction " + savepoint.getSavepointName(), e);
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public CompiledStatement compileStatement(String str, StatementBuilder.StatementType statementType, FieldType[] fieldTypeArr, int i, boolean z) {
        AndroidCompiledStatement androidCompiledStatement = new AndroidCompiledStatement(str, this.db, statementType, this.cancelQueriesEnabled, z);
        logger.trace("{}: compiled statement got {}: {}", this, androidCompiledStatement, str);
        return androidCompiledStatement;
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public int delete(String str, Object[] objArr, FieldType[] fieldTypeArr) throws SQLException {
        return execute(str, objArr, fieldTypeArr, "deleted");
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public int executeStatement(String str, int i) throws SQLException {
        return AndroidCompiledStatement.execSql(this.db, str, str, NO_STRING_ARGS);
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public Connection getUnderlyingConnection() {
        return null;
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public int insert(String str, Object[] objArr, FieldType[] fieldTypeArr, GeneratedKeyHolder generatedKeyHolder) throws SQLException {
        SQLiteStatement sQLiteStatementCompileStatement = null;
        try {
            try {
                sQLiteStatementCompileStatement = this.db.compileStatement(str);
                bindArgs(sQLiteStatementCompileStatement, objArr, fieldTypeArr);
                long jExecuteInsert = sQLiteStatementCompileStatement.executeInsert();
                if (generatedKeyHolder != null) {
                    generatedKeyHolder.addKey(Long.valueOf(jExecuteInsert));
                }
                logger.trace("{}: insert statement is compiled and executed, changed {}: {}", (Object) this, (Object) 1, (Object) str);
                closeQuietly(sQLiteStatementCompileStatement);
                return 1;
            } catch (android.database.SQLException e) {
                throw new SQLException("inserting to database failed: " + str, e);
            }
        } catch (Throwable th) {
            closeQuietly(sQLiteStatementCompileStatement);
            throw th;
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public boolean isAutoCommit() throws SQLException {
        try {
            boolean zInTransaction = this.db.inTransaction();
            logger.trace("{}: in transaction is {}", this, Boolean.valueOf(zInTransaction));
            return !zInTransaction;
        } catch (android.database.SQLException e) {
            throw new SQLException("problems getting auto-commit from database", e);
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public boolean isAutoCommitSupported() {
        return true;
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public boolean isClosed() throws SQLException {
        try {
            boolean zIsOpen = this.db.isOpen();
            logger.trace("{}: db {} isOpen returned {}", this, this.db, Boolean.valueOf(zIsOpen));
            return !zIsOpen;
        } catch (android.database.SQLException e) {
            throw new SQLException("problems detecting if the database is closed", e);
        }
    }

    public boolean isReadWrite() {
        return this.readWrite;
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public boolean isTableExists(String str) {
        Cursor cursorRawQuery = this.db.rawQuery("SELECT DISTINCT tbl_name FROM sqlite_master WHERE tbl_name = ?", new String[]{str});
        try {
            boolean z = cursorRawQuery.getCount() > 0;
            logger.trace("{}: isTableExists '{}' returned {}", this, str, Boolean.valueOf(z));
            return z;
        } finally {
            cursorRawQuery.close();
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public long queryForLong(String str) throws SQLException {
        SQLiteStatement sQLiteStatementCompileStatement = null;
        try {
            try {
                sQLiteStatementCompileStatement = this.db.compileStatement(str);
                long jSimpleQueryForLong = sQLiteStatementCompileStatement.simpleQueryForLong();
                logger.trace("{}: query for long simple query returned {}: {}", this, Long.valueOf(jSimpleQueryForLong), str);
                return jSimpleQueryForLong;
            } catch (android.database.SQLException e) {
                throw new SQLException("queryForLong from database failed: " + str, e);
            }
        } finally {
            closeQuietly(sQLiteStatementCompileStatement);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0 */
    /* JADX WARN: Type inference failed for: r1v1 */
    /* JADX WARN: Type inference failed for: r1v2 */
    /* JADX WARN: Type inference failed for: r1v4 */
    /* JADX WARN: Type inference failed for: r1v5 */
    /* JADX WARN: Type inference failed for: r1v6, types: [com.j256.ormlite.android.AndroidDatabaseResults, com.j256.ormlite.support.DatabaseResults, java.lang.AutoCloseable] */
    /* JADX WARN: Type inference failed for: r1v7 */
    @Override // com.j256.ormlite.support.DatabaseConnection
    public <T> Object queryForOne(String str, Object[] objArr, FieldType[] fieldTypeArr, GenericRowMapper<T> genericRowMapper, ObjectCache objectCache) throws Throwable {
        Cursor cursorRawQuery;
        ?? androidDatabaseResults;
        Cursor cursor = null;
        try {
            cursorRawQuery = this.db.rawQuery(str, toStrings(objArr));
            try {
                androidDatabaseResults = new AndroidDatabaseResults(cursorRawQuery, objectCache, true);
            } catch (android.database.SQLException e) {
                e = e;
                androidDatabaseResults = 0;
            } catch (Throwable th) {
                th = th;
                IOUtils.closeQuietly((AutoCloseable) cursor);
                closeQuietly(cursorRawQuery);
                throw th;
            }
            try {
                logger.trace("{}: queried for one result: {}", this, str);
                if (!androidDatabaseResults.first()) {
                    IOUtils.closeQuietly((AutoCloseable) androidDatabaseResults);
                    closeQuietly(cursorRawQuery);
                    return null;
                }
                T tMapRow = genericRowMapper.mapRow(androidDatabaseResults);
                if (!androidDatabaseResults.next()) {
                    IOUtils.closeQuietly((AutoCloseable) androidDatabaseResults);
                    closeQuietly(cursorRawQuery);
                    return tMapRow;
                }
                Object obj = DatabaseConnection.MORE_THAN_ONE;
                IOUtils.closeQuietly((AutoCloseable) androidDatabaseResults);
                closeQuietly(cursorRawQuery);
                return obj;
            } catch (android.database.SQLException e2) {
                e = e2;
                cursor = cursorRawQuery;
                androidDatabaseResults = androidDatabaseResults;
                try {
                    throw new SQLException("queryForOne from database failed: " + str, e);
                } catch (Throwable th2) {
                    th = th2;
                    cursorRawQuery = cursor;
                    cursor = androidDatabaseResults;
                    IOUtils.closeQuietly((AutoCloseable) cursor);
                    closeQuietly(cursorRawQuery);
                    throw th;
                }
            } catch (Throwable th3) {
                th = th3;
                cursor = androidDatabaseResults;
                IOUtils.closeQuietly((AutoCloseable) cursor);
                closeQuietly(cursorRawQuery);
                throw th;
            }
        } catch (android.database.SQLException e3) {
            e = e3;
            androidDatabaseResults = 0;
        } catch (Throwable th4) {
            th = th4;
            cursorRawQuery = null;
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public void releaseSavePoint(Savepoint savepoint) {
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public void rollback(Savepoint savepoint) throws SQLException {
        try {
            this.db.endTransaction();
            if (savepoint == null) {
                logger.trace("{}: transaction is ended, unsuccessfully", this);
            } else {
                logger.trace("{}: transaction {} is ended, unsuccessfully", this, savepoint.getSavepointName());
            }
        } catch (android.database.SQLException e) {
            if (savepoint == null) {
                throw new SQLException("problems rolling back transaction", e);
            }
            throw new SQLException("problems rolling back transaction " + savepoint.getSavepointName(), e);
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public void setAutoCommit(boolean z) {
        if (!z) {
            if (this.db.inTransaction()) {
                return;
            }
            this.db.beginTransaction();
        } else if (this.db.inTransaction()) {
            this.db.setTransactionSuccessful();
            this.db.endTransaction();
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public Savepoint setSavePoint(String str) throws SQLException {
        try {
            this.db.beginTransaction();
            logger.trace("{}: save-point set with name {}", this, str);
            return new OurSavePoint(str);
        } catch (android.database.SQLException e) {
            throw new SQLException(AbstractC0147y.d("problems beginning transaction ", str), e);
        }
    }

    public String toString() {
        return getClass().getSimpleName() + "@" + Integer.toHexString(super.hashCode());
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public int update(String str, Object[] objArr, FieldType[] fieldTypeArr) throws SQLException {
        return execute(str, objArr, fieldTypeArr, "updated");
    }

    public AndroidDatabaseConnection(SQLiteDatabase sQLiteDatabase, boolean z, boolean z2) {
        this.db = sQLiteDatabase;
        this.readWrite = z;
        this.cancelQueriesEnabled = z2;
        logger.trace("{}: db {} opened, read-write = {}", this, sQLiteDatabase, Boolean.valueOf(z));
    }

    private void closeQuietly(Cursor cursor) {
        if (cursor != null) {
            cursor.close();
        }
    }

    private void closeQuietly(SQLiteStatement sQLiteStatement) {
        if (sQLiteStatement != null) {
            sQLiteStatement.close();
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnection
    public long queryForLong(String str, Object[] objArr, FieldType[] fieldTypeArr) throws Throwable {
        AndroidDatabaseResults androidDatabaseResults;
        android.database.SQLException e;
        Cursor cursorRawQuery;
        Cursor cursor = null;
        try {
            cursorRawQuery = this.db.rawQuery(str, toStrings(objArr));
            try {
                androidDatabaseResults = new AndroidDatabaseResults(cursorRawQuery, null, false);
                try {
                    try {
                        long j = androidDatabaseResults.first() ? androidDatabaseResults.getLong(0) : 0L;
                        logger.trace("{}: query for long raw query returned {}: {}", this, Long.valueOf(j), str);
                        closeQuietly(cursorRawQuery);
                        IOUtils.closeQuietly(androidDatabaseResults);
                        return j;
                    } catch (android.database.SQLException e2) {
                        e = e2;
                        throw new SQLException("queryForLong from database failed: " + str, e);
                    }
                } catch (Throwable th) {
                    th = th;
                    cursor = cursorRawQuery;
                    closeQuietly(cursor);
                    IOUtils.closeQuietly(androidDatabaseResults);
                    throw th;
                }
            } catch (android.database.SQLException e3) {
                androidDatabaseResults = null;
                e = e3;
            } catch (Throwable th2) {
                th = th2;
                androidDatabaseResults = null;
                cursor = cursorRawQuery;
                closeQuietly(cursor);
                IOUtils.closeQuietly(androidDatabaseResults);
                throw th;
            }
        } catch (android.database.SQLException e4) {
            androidDatabaseResults = null;
            e = e4;
            cursorRawQuery = null;
        } catch (Throwable th3) {
            th = th3;
            androidDatabaseResults = null;
            closeQuietly(cursor);
            IOUtils.closeQuietly(androidDatabaseResults);
            throw th;
        }
    }
}
