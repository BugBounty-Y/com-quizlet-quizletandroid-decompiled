package com.j256.ormlite.table;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.logger.Logger;
import com.j256.ormlite.logger.LoggerFactory;
import com.j256.ormlite.misc.IOUtils;
import com.j256.ormlite.stmt.StatementBuilder;
import com.j256.ormlite.support.CompiledStatement;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.support.DatabaseConnection;
import com.j256.ormlite.support.DatabaseResults;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class SchemaUtils {
    private static Logger logger = LoggerFactory.getLogger((Class<?>) SchemaUtils.class);
    private static final FieldType[] noFieldTypes = new FieldType[0];

    private SchemaUtils() {
    }

    private static <T, ID> void addCreateSchemaStatements(DatabaseType databaseType, String str, List<String> list, List<String> list2, boolean z, boolean z2) {
        StringBuilder sb = new StringBuilder(256);
        if (z2) {
            logger.info("creating schema '{}'", str);
        }
        sb.append("CREATE SCHEMA ");
        if (z && databaseType.isCreateIfNotExistsSupported()) {
            sb.append("IF NOT EXISTS ");
        }
        databaseType.appendEscapedEntityName(sb, str);
        databaseType.appendCreateSchemaSuffix(sb);
        list.add(sb.toString());
    }

    private static <T, ID> void addDropSchemaStatements(DatabaseType databaseType, String str, List<String> list, boolean z) {
        StringBuilder sb = new StringBuilder(64);
        if (z) {
            logger.info("dropping schema '{}'", str);
        }
        sb.append("DROP SCHEMA ");
        databaseType.appendEscapedEntityName(sb, str);
        sb.append(' ');
        list.add(sb.toString());
    }

    public static <T> int createSchema(ConnectionSource connectionSource, Class<T> cls) throws SQLException {
        return doCreateSchema(connectionSource, DaoManager.createDao(connectionSource, cls).getTableInfo().getSchemaName(), false);
    }

    public static <T> int createSchemaIfNotExists(ConnectionSource connectionSource, Class<T> cls) throws SQLException {
        Dao daoCreateDao = DaoManager.createDao(connectionSource, cls);
        return doCreateSchema(daoCreateDao.getConnectionSource(), daoCreateDao.getTableInfo().getSchemaName(), true);
    }

    private static <T, ID> int doCreateSchema(ConnectionSource connectionSource, String str, boolean z) throws SQLException {
        DatabaseType databaseType = connectionSource.getDatabaseType();
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        addCreateSchemaStatements(databaseType, str, arrayList, arrayList2, z, true);
        DatabaseConnection readWriteConnection = connectionSource.getReadWriteConnection(str);
        try {
            return doStatements(readWriteConnection, "create", arrayList, false, databaseType.isCreateSchemaReturnsNegative(), databaseType.isCreateSchemaReturnsZero()) + doCreateTestQueries(readWriteConnection, databaseType, arrayList2);
        } finally {
            connectionSource.releaseConnection(readWriteConnection);
        }
    }

    private static int doCreateTestQueries(DatabaseConnection databaseConnection, DatabaseType databaseType, List<String> list) throws Throwable {
        Throwable th;
        SQLException sQLException;
        DatabaseConnection databaseConnection2;
        CompiledStatement compiledStatementCompileStatement;
        int i = 0;
        for (String str : list) {
            CompiledStatement compiledStatement = null;
            try {
                try {
                    databaseConnection2 = databaseConnection;
                    compiledStatementCompileStatement = databaseConnection2.compileStatement(str, StatementBuilder.StatementType.SELECT, noFieldTypes, -1, false);
                } catch (SQLException e) {
                    sQLException = e;
                }
            } catch (Throwable th2) {
                th = th2;
            }
            try {
                DatabaseResults databaseResultsRunQuery = compiledStatementCompileStatement.runQuery(null);
                int i2 = 0;
                for (boolean zFirst = databaseResultsRunQuery.first(); zFirst; zFirst = databaseResultsRunQuery.next()) {
                    i2++;
                }
                logger.info("executing create schema after-query got {} results: {}", Integer.valueOf(i2), str);
                IOUtils.closeThrowSqlException(compiledStatementCompileStatement, "compiled statement");
                i++;
                databaseConnection = databaseConnection2;
            } catch (SQLException e2) {
                sQLException = e2;
                compiledStatement = compiledStatementCompileStatement;
                throw new SQLException("executing create schema after-query failed: " + str, sQLException);
            } catch (Throwable th3) {
                th = th3;
                compiledStatement = compiledStatementCompileStatement;
                IOUtils.closeThrowSqlException(compiledStatement, "compiled statement");
                throw th;
            }
        }
        return i;
    }

    private static <T, ID> int doDropSchema(DatabaseType databaseType, ConnectionSource connectionSource, String str, boolean z) throws SQLException {
        ArrayList arrayList = new ArrayList();
        addDropSchemaStatements(databaseType, str, arrayList, true);
        DatabaseConnection readWriteConnection = connectionSource.getReadWriteConnection(str);
        try {
            return doStatements(readWriteConnection, "drop", arrayList, z, databaseType.isCreateSchemaReturnsNegative(), false);
        } finally {
            connectionSource.releaseConnection(readWriteConnection);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x006c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static int doStatements(com.j256.ormlite.support.DatabaseConnection r11, java.lang.String r12, java.util.Collection<java.lang.String> r13, boolean r14, boolean r15, boolean r16) throws java.sql.SQLException {
        /*
            java.lang.String r1 = "compiled statement"
            java.util.Iterator r13 = r13.iterator()
            r2 = 0
            r3 = r2
        L8:
            boolean r0 = r13.hasNext()
            if (r0 == 0) goto Lac
            java.lang.Object r0 = r13.next()
            r5 = r0
            java.lang.String r5 = (java.lang.String) r5
            r10 = 0
            com.j256.ormlite.stmt.StatementBuilder$StatementType r6 = com.j256.ormlite.stmt.StatementBuilder.StatementType.EXECUTE     // Catch: java.lang.Throwable -> L34 java.sql.SQLException -> L3a
            com.j256.ormlite.field.FieldType[] r7 = com.j256.ormlite.table.SchemaUtils.noFieldTypes     // Catch: java.lang.Throwable -> L34 java.sql.SQLException -> L3a
            r8 = -1
            r9 = 0
            r4 = r11
            com.j256.ormlite.support.CompiledStatement r10 = r4.compileStatement(r5, r6, r7, r8, r9)     // Catch: java.lang.Throwable -> L34 java.sql.SQLException -> L3a
            int r4 = r10.runExecute()     // Catch: java.lang.Throwable -> L34 java.sql.SQLException -> L3a
            com.j256.ormlite.logger.Logger r0 = com.j256.ormlite.table.SchemaUtils.logger     // Catch: java.lang.Throwable -> L34 java.sql.SQLException -> L38
            java.lang.String r6 = "executed {} schema statement changed {} rows: {}"
            java.lang.Integer r7 = java.lang.Integer.valueOf(r4)     // Catch: java.lang.Throwable -> L34 java.sql.SQLException -> L38
            r0.info(r6, r12, r7, r5)     // Catch: java.lang.Throwable -> L34 java.sql.SQLException -> L38
        L30:
            com.j256.ormlite.misc.IOUtils.closeThrowSqlException(r10, r1)
            goto L46
        L34:
            r0 = move-exception
            r11 = r0
            goto La8
        L38:
            r0 = move-exception
            goto L3c
        L3a:
            r0 = move-exception
            r4 = r2
        L3c:
            if (r14 == 0) goto L91
            com.j256.ormlite.logger.Logger r6 = com.j256.ormlite.table.SchemaUtils.logger     // Catch: java.lang.Throwable -> L34
            java.lang.String r7 = "ignoring {} error '{}' for statement: {}"
            r6.info(r7, r12, r0, r5)     // Catch: java.lang.Throwable -> L34
            goto L30
        L46:
            if (r4 >= 0) goto L6c
            if (r15 == 0) goto L4b
            goto L8d
        L4b:
            java.sql.SQLException r11 = new java.sql.SQLException
            java.lang.StringBuilder r12 = new java.lang.StringBuilder
            java.lang.String r13 = "SQL statement "
            r12.<init>(r13)
            r12.append(r5)
            java.lang.String r13 = " updated "
            r12.append(r13)
            r12.append(r4)
            java.lang.String r13 = " rows, we were expecting >= 0"
            r12.append(r13)
            java.lang.String r12 = r12.toString()
            r11.<init>(r12)
            throw r11
        L6c:
            if (r4 <= 0) goto L8d
            if (r16 != 0) goto L71
            goto L8d
        L71:
            java.sql.SQLException r11 = new java.sql.SQLException
            java.lang.StringBuilder r12 = new java.lang.StringBuilder
            java.lang.String r13 = "SQL statement updated "
            r12.<init>(r13)
            r12.append(r4)
            java.lang.String r13 = " rows, we were expecting == 0: "
            r12.append(r13)
            r12.append(r5)
            java.lang.String r12 = r12.toString()
            r11.<init>(r12)
            throw r11
        L8d:
            int r3 = r3 + 1
            goto L8
        L91:
            java.sql.SQLException r11 = new java.sql.SQLException     // Catch: java.lang.Throwable -> L34
            java.lang.StringBuilder r12 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L34
            r12.<init>()     // Catch: java.lang.Throwable -> L34
            java.lang.String r13 = "SQL statement failed: "
            r12.append(r13)     // Catch: java.lang.Throwable -> L34
            r12.append(r5)     // Catch: java.lang.Throwable -> L34
            java.lang.String r12 = r12.toString()     // Catch: java.lang.Throwable -> L34
            r11.<init>(r12, r0)     // Catch: java.lang.Throwable -> L34
            throw r11     // Catch: java.lang.Throwable -> L34
        La8:
            com.j256.ormlite.misc.IOUtils.closeThrowSqlException(r10, r1)
            throw r11
        Lac:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.j256.ormlite.table.SchemaUtils.doStatements(com.j256.ormlite.support.DatabaseConnection, java.lang.String, java.util.Collection, boolean, boolean, boolean):int");
    }

    public static <T, ID> int dropSchema(ConnectionSource connectionSource, Class<T> cls, boolean z) throws SQLException {
        Dao daoCreateDao = DaoManager.createDao(connectionSource, cls);
        return dropSchema(daoCreateDao.getConnectionSource(), daoCreateDao.getTableInfo().getSchemaName(), z);
    }

    public static <T> List<String> getCreateSchemaStatements(DatabaseType databaseType, String str) {
        ArrayList arrayList = new ArrayList();
        addCreateSchemaStatements(databaseType, str, arrayList, arrayList, false, false);
        return arrayList;
    }

    public static int createSchema(Dao<?, ?> dao) throws SQLException {
        return doCreateSchema(dao.getConnectionSource(), dao.getTableInfo().getSchemaName(), false);
    }

    public static <T> int createSchemaIfNotExists(ConnectionSource connectionSource, String str) throws SQLException {
        return doCreateSchema(connectionSource, str, true);
    }

    public static <T, ID> int dropSchema(ConnectionSource connectionSource, String str, boolean z) throws SQLException {
        return doDropSchema(connectionSource.getDatabaseType(), connectionSource, str, z);
    }

    public static <T> int createSchema(ConnectionSource connectionSource, String str) throws SQLException {
        return doCreateSchema(connectionSource, str, false);
    }
}
