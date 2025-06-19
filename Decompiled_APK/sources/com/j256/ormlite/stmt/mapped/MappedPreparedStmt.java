package com.j256.ormlite.stmt.mapped;

import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.stmt.ArgumentHolder;
import com.j256.ormlite.stmt.PreparedDelete;
import com.j256.ormlite.stmt.PreparedQuery;
import com.j256.ormlite.stmt.PreparedUpdate;
import com.j256.ormlite.stmt.StatementBuilder;
import com.j256.ormlite.support.CompiledStatement;
import com.j256.ormlite.support.DatabaseConnection;
import com.j256.ormlite.table.TableInfo;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public class MappedPreparedStmt<T, ID> extends BaseMappedQuery<T, ID> implements PreparedQuery<T>, PreparedDelete<T>, PreparedUpdate<T> {
    private final ArgumentHolder[] argHolders;
    private final boolean cacheStore;
    private final Long limit;
    private final StatementBuilder.StatementType type;

    public MappedPreparedStmt(Dao<T, ID> dao, TableInfo<T, ID> tableInfo, String str, FieldType[] fieldTypeArr, FieldType[] fieldTypeArr2, ArgumentHolder[] argumentHolderArr, Long l, StatementBuilder.StatementType statementType, boolean z) {
        super(dao, tableInfo, str, fieldTypeArr, fieldTypeArr2);
        this.argHolders = argumentHolderArr;
        this.limit = l;
        this.type = statementType;
        this.cacheStore = z;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0021  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private com.j256.ormlite.support.CompiledStatement assignStatementArguments(com.j256.ormlite.support.CompiledStatement r6) throws java.sql.SQLException {
        /*
            r5 = this;
            java.lang.Long r0 = r5.limit     // Catch: java.lang.Throwable -> Lc
            if (r0 == 0) goto Le
            int r0 = r0.intValue()     // Catch: java.lang.Throwable -> Lc
            r6.setMaxRows(r0)     // Catch: java.lang.Throwable -> Lc
            goto Le
        Lc:
            r0 = move-exception
            goto L63
        Le:
            com.j256.ormlite.logger.Logger r0 = com.j256.ormlite.stmt.mapped.BaseMappedStatement.logger     // Catch: java.lang.Throwable -> Lc
            com.j256.ormlite.logger.Level r1 = com.j256.ormlite.logger.Level.TRACE     // Catch: java.lang.Throwable -> Lc
            boolean r0 = r0.isLevelEnabled(r1)     // Catch: java.lang.Throwable -> Lc
            if (r0 == 0) goto L21
            com.j256.ormlite.stmt.ArgumentHolder[] r0 = r5.argHolders     // Catch: java.lang.Throwable -> Lc
            int r1 = r0.length     // Catch: java.lang.Throwable -> Lc
            if (r1 <= 0) goto L21
            int r0 = r0.length     // Catch: java.lang.Throwable -> Lc
            java.lang.Object[] r0 = new java.lang.Object[r0]     // Catch: java.lang.Throwable -> Lc
            goto L22
        L21:
            r0 = 0
        L22:
            r1 = 0
        L23:
            com.j256.ormlite.stmt.ArgumentHolder[] r2 = r5.argHolders     // Catch: java.lang.Throwable -> Lc
            int r3 = r2.length     // Catch: java.lang.Throwable -> Lc
            if (r1 >= r3) goto L4b
            r2 = r2[r1]     // Catch: java.lang.Throwable -> Lc
            java.lang.Object r2 = r2.getSqlArgValue()     // Catch: java.lang.Throwable -> Lc
            com.j256.ormlite.field.FieldType[] r3 = r5.argFieldTypes     // Catch: java.lang.Throwable -> Lc
            r3 = r3[r1]     // Catch: java.lang.Throwable -> Lc
            if (r3 != 0) goto L3d
            com.j256.ormlite.stmt.ArgumentHolder[] r3 = r5.argHolders     // Catch: java.lang.Throwable -> Lc
            r3 = r3[r1]     // Catch: java.lang.Throwable -> Lc
            com.j256.ormlite.field.SqlType r3 = r3.getSqlType()     // Catch: java.lang.Throwable -> Lc
            goto L41
        L3d:
            com.j256.ormlite.field.SqlType r3 = r3.getSqlType()     // Catch: java.lang.Throwable -> Lc
        L41:
            r6.setObject(r1, r2, r3)     // Catch: java.lang.Throwable -> Lc
            if (r0 == 0) goto L48
            r0[r1] = r2     // Catch: java.lang.Throwable -> Lc
        L48:
            int r1 = r1 + 1
            goto L23
        L4b:
            com.j256.ormlite.logger.Logger r1 = com.j256.ormlite.stmt.mapped.BaseMappedStatement.logger     // Catch: java.lang.Throwable -> Lc
            java.lang.String r3 = "prepared statement '{}' with {} args"
            java.lang.String r4 = r5.statement     // Catch: java.lang.Throwable -> Lc
            int r2 = r2.length     // Catch: java.lang.Throwable -> Lc
            java.lang.Integer r2 = java.lang.Integer.valueOf(r2)     // Catch: java.lang.Throwable -> Lc
            r1.debug(r3, r4, r2)     // Catch: java.lang.Throwable -> Lc
            if (r0 == 0) goto L62
            com.j256.ormlite.logger.Logger r1 = com.j256.ormlite.stmt.mapped.BaseMappedStatement.logger     // Catch: java.lang.Throwable -> Lc
            java.lang.String r2 = "prepared statement arguments: {}"
            r1.trace(r2, r0)     // Catch: java.lang.Throwable -> Lc
        L62:
            return r6
        L63:
            java.lang.String r1 = "statement"
            com.j256.ormlite.misc.IOUtils.closeThrowSqlException(r6, r1)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.j256.ormlite.stmt.mapped.MappedPreparedStmt.assignStatementArguments(com.j256.ormlite.support.CompiledStatement):com.j256.ormlite.support.CompiledStatement");
    }

    @Override // com.j256.ormlite.stmt.PreparedQuery, com.j256.ormlite.stmt.PreparedStmt
    public CompiledStatement compile(DatabaseConnection databaseConnection, StatementBuilder.StatementType statementType) throws SQLException {
        return compile(databaseConnection, statementType, -1);
    }

    @Override // com.j256.ormlite.stmt.PreparedQuery, com.j256.ormlite.stmt.PreparedStmt
    public int getNumArgs() {
        ArgumentHolder[] argumentHolderArr = this.argHolders;
        if (argumentHolderArr == null) {
            return 0;
        }
        return argumentHolderArr.length;
    }

    @Override // com.j256.ormlite.stmt.PreparedQuery, com.j256.ormlite.stmt.PreparedStmt
    public String getStatement() {
        return this.statement;
    }

    @Override // com.j256.ormlite.stmt.PreparedQuery, com.j256.ormlite.stmt.PreparedStmt
    public StatementBuilder.StatementType getType() {
        return this.type;
    }

    @Override // com.j256.ormlite.stmt.PreparedQuery, com.j256.ormlite.stmt.PreparedStmt
    public void setArgumentHolderValue(int i, Object obj) throws SQLException {
        if (i < 0) {
            throw new SQLException(AbstractC0147y.c(i, "argument holder index ", " must be >= 0"));
        }
        ArgumentHolder[] argumentHolderArr = this.argHolders;
        if (argumentHolderArr.length <= i) {
            throw new SQLException(a.r(a.v(i, "argument holder index ", " is not valid, only "), this.argHolders.length, " in statement (index starts at 0)"));
        }
        argumentHolderArr[i].setValue(obj);
    }

    @Override // com.j256.ormlite.stmt.PreparedQuery, com.j256.ormlite.stmt.PreparedStmt
    public CompiledStatement compile(DatabaseConnection databaseConnection, StatementBuilder.StatementType statementType, int i) throws SQLException {
        if (this.type == statementType) {
            return assignStatementArguments(databaseConnection.compileStatement(this.statement, statementType, this.argFieldTypes, i, this.cacheStore));
        }
        throw new SQLException("Could not compile this " + this.type + " statement since the caller is expecting a " + statementType + " statement.  Check your QueryBuilder methods.");
    }
}
