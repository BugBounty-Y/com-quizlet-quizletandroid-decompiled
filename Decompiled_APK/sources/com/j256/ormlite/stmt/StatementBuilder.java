package com.j256.ormlite.stmt;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.logger.Logger;
import com.j256.ormlite.logger.LoggerFactory;
import com.j256.ormlite.stmt.mapped.MappedPreparedStmt;
import com.j256.ormlite.table.TableInfo;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public abstract class StatementBuilder<T, ID> {
    private static final ArgumentHolder[] EMPTY_ARGUMENT_HOLDERS = new ArgumentHolder[0];
    private static final FieldType[] EMPTY_FIELD_TYPES = new FieldType[0];
    private static final Logger logger = LoggerFactory.getLogger((Class<?>) StatementBuilder.class);
    protected boolean addTableName;
    protected final Dao<T, ID> dao;
    protected final DatabaseType databaseType;
    protected final TableInfo<T, ID> tableInfo;
    protected final String tableName;
    protected StatementType type;
    protected Where<T, ID> where = null;

    public static class StatementInfo {
        private final List<ArgumentHolder> argList;
        private final String statement;

        public StatementInfo(String str, List<ArgumentHolder> list) {
            this.argList = list;
            this.statement = str;
        }

        public List<ArgumentHolder> getArgList() {
            return this.argList;
        }

        public String getStatement() {
            return this.statement;
        }
    }

    public enum StatementType {
        SELECT(true, true, false, false),
        SELECT_LONG(true, true, false, false),
        SELECT_RAW(true, true, false, false),
        UPDATE(true, false, true, false),
        DELETE(true, false, true, false),
        EXECUTE(false, false, false, true);

        private final boolean okForExecute;
        private final boolean okForQuery;
        private final boolean okForStatementBuilder;
        private final boolean okForUpdate;

        StatementType(boolean z, boolean z2, boolean z3, boolean z4) {
            this.okForStatementBuilder = z;
            this.okForQuery = z2;
            this.okForUpdate = z3;
            this.okForExecute = z4;
        }

        public boolean isOkForExecute() {
            return this.okForExecute;
        }

        public boolean isOkForQuery() {
            return this.okForQuery;
        }

        public boolean isOkForStatementBuilder() {
            return this.okForStatementBuilder;
        }

        public boolean isOkForUpdate() {
            return this.okForUpdate;
        }
    }

    public enum WhereOperation {
        FIRST("WHERE ", null),
        AND("AND (", ") "),
        OR("OR (", ") ");

        private final String after;
        private final String before;

        WhereOperation(String str, String str2) {
            this.before = str;
            this.after = str2;
        }

        public void appendAfter(StringBuilder sb) {
            String str = this.after;
            if (str != null) {
                sb.append(str);
            }
        }

        public void appendBefore(StringBuilder sb) {
            String str = this.before;
            if (str != null) {
                sb.append(str);
            }
        }
    }

    public StatementBuilder(DatabaseType databaseType, TableInfo<T, ID> tableInfo, Dao<T, ID> dao, StatementType statementType) {
        this.databaseType = databaseType;
        this.tableInfo = tableInfo;
        this.tableName = tableInfo.getTableName();
        this.dao = dao;
        this.type = statementType;
        if (statementType.isOkForStatementBuilder()) {
            return;
        }
        throw new IllegalStateException("Building a statement from a " + statementType + " statement is not allowed");
    }

    public abstract void appendStatementEnd(StringBuilder sb, List<ArgumentHolder> list) throws SQLException;

    public abstract void appendStatementStart(StringBuilder sb, List<ArgumentHolder> list) throws SQLException;

    public void appendStatementString(StringBuilder sb, List<ArgumentHolder> list) throws SQLException {
        appendStatementStart(sb, list);
        appendWhereStatement(sb, list, WhereOperation.FIRST);
        appendStatementEnd(sb, list);
    }

    public boolean appendWhereStatement(StringBuilder sb, List<ArgumentHolder> list, WhereOperation whereOperation) throws SQLException {
        if (this.where == null) {
            return whereOperation == WhereOperation.FIRST;
        }
        whereOperation.appendBefore(sb);
        this.where.appendSql(this.addTableName ? getTableName() : null, sb, list);
        whereOperation.appendAfter(sb);
        return false;
    }

    public String buildStatementString(List<ArgumentHolder> list) throws SQLException {
        StringBuilder sb = new StringBuilder(128);
        appendStatementString(sb, list);
        int length = sb.length();
        if (length > 0) {
            int i = length - 1;
            if (sb.charAt(i) == ' ') {
                sb.setLength(i);
            }
        }
        String string = sb.toString();
        logger.debug("built statement {}", string);
        return string;
    }

    public FieldType[] getResultFieldTypes() {
        return null;
    }

    public String getTableName() {
        return this.tableName;
    }

    public StatementType getType() {
        return this.type;
    }

    public MappedPreparedStmt<T, ID> prepareStatement(Long l, boolean z) throws SQLException {
        FieldType[] fieldTypeArr;
        ArgumentHolder[] argumentHolderArr;
        ArrayList arrayList = new ArrayList();
        String strBuildStatementString = buildStatementString(arrayList);
        if (arrayList.isEmpty()) {
            argumentHolderArr = EMPTY_ARGUMENT_HOLDERS;
            fieldTypeArr = EMPTY_FIELD_TYPES;
        } else {
            ArgumentHolder[] argumentHolderArr2 = (ArgumentHolder[]) arrayList.toArray(new ArgumentHolder[arrayList.size()]);
            FieldType[] fieldTypeArr2 = new FieldType[arrayList.size()];
            for (int i = 0; i < argumentHolderArr2.length; i++) {
                fieldTypeArr2[i] = argumentHolderArr2[i].getFieldType();
            }
            fieldTypeArr = fieldTypeArr2;
            argumentHolderArr = argumentHolderArr2;
        }
        FieldType[] resultFieldTypes = getResultFieldTypes();
        Dao<T, ID> dao = this.dao;
        TableInfo<T, ID> tableInfo = this.tableInfo;
        if (this.databaseType.isLimitSqlSupported()) {
            l = null;
        }
        return new MappedPreparedStmt<>(dao, tableInfo, strBuildStatementString, fieldTypeArr, resultFieldTypes, argumentHolderArr, l, this.type, z);
    }

    public StatementInfo prepareStatementInfo() throws SQLException {
        ArrayList arrayList = new ArrayList();
        return new StatementInfo(buildStatementString(arrayList), arrayList);
    }

    public String prepareStatementString() throws SQLException {
        return buildStatementString(new ArrayList());
    }

    public void reset() {
        this.where = null;
    }

    public void setWhere(Where<T, ID> where) {
        this.where = where;
    }

    public boolean shouldPrependTableNameToColumns() {
        return false;
    }

    public FieldType verifyColumnName(String str) {
        return this.tableInfo.getFieldTypeByColumnName(str);
    }

    public Where<T, ID> where() {
        Where<T, ID> where = new Where<>(this.tableInfo, this, this.databaseType);
        this.where = where;
        return where;
    }
}
