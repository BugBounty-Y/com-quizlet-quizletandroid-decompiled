package com.j256.ormlite.stmt;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.stmt.StatementBuilder;
import com.j256.ormlite.stmt.query.Clause;
import com.j256.ormlite.stmt.query.SetExpression;
import com.j256.ormlite.stmt.query.SetValue;
import com.j256.ormlite.table.TableInfo;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class UpdateBuilder<T, ID> extends StatementBuilder<T, ID> {
    private Long limit;
    private List<Clause> updateClauseList;

    public UpdateBuilder(DatabaseType databaseType, TableInfo<T, ID> tableInfo, Dao<T, ID> dao) {
        super(databaseType, tableInfo, dao, StatementBuilder.StatementType.UPDATE);
        this.updateClauseList = null;
    }

    private void addUpdateColumnToList(String str, Clause clause) {
        if (this.updateClauseList == null) {
            this.updateClauseList = new ArrayList();
        }
        this.updateClauseList.add(clause);
    }

    private void appendLimit(StringBuilder sb) {
        Long l = this.limit;
        if (l != null) {
            this.databaseType.appendUpdateLimitValue(sb, l.longValue());
        }
    }

    @Override // com.j256.ormlite.stmt.StatementBuilder
    public void appendStatementEnd(StringBuilder sb, List<ArgumentHolder> list) {
        if (this.databaseType.isLimitUpdateAtEndSupported()) {
            appendLimit(sb);
        }
    }

    @Override // com.j256.ormlite.stmt.StatementBuilder
    public void appendStatementStart(StringBuilder sb, List<ArgumentHolder> list) throws SQLException {
        List<Clause> list2 = this.updateClauseList;
        if (list2 == null || list2.isEmpty()) {
            throw new IllegalArgumentException("UPDATE statements must have at least one SET column");
        }
        sb.append("UPDATE ");
        if (this.tableInfo.getSchemaName() != null && this.tableInfo.getSchemaName().length() > 0) {
            this.databaseType.appendEscapedEntityName(sb, this.tableInfo.getSchemaName());
            sb.append('.');
        }
        if (this.databaseType.isLimitAfterUpdateSupported()) {
            appendLimit(sb);
        }
        this.databaseType.appendEscapedEntityName(sb, this.tableInfo.getTableName());
        sb.append(" SET ");
        boolean z = true;
        for (Clause clause : this.updateClauseList) {
            if (z) {
                z = false;
            } else {
                sb.append(',');
            }
            clause.appendSql(this.databaseType, null, sb, list, null);
        }
    }

    public void escapeColumnName(StringBuilder sb, String str) {
        this.databaseType.appendEscapedEntityName(sb, str);
    }

    public void escapeValue(StringBuilder sb, String str) {
        this.databaseType.appendEscapedWord(sb, str);
    }

    public UpdateBuilder<T, ID> limit(Long l) {
        this.limit = l;
        return this;
    }

    public PreparedUpdate<T> prepare() throws SQLException {
        return super.prepareStatement(this.limit, false);
    }

    @Override // com.j256.ormlite.stmt.StatementBuilder
    public void reset() {
        super.reset();
        this.updateClauseList = null;
        this.limit = null;
    }

    public int update() throws SQLException {
        return this.dao.update((PreparedUpdate) prepare());
    }

    public UpdateBuilder<T, ID> updateColumnExpression(String str, String str2) throws SQLException {
        FieldType fieldTypeVerifyColumnName = verifyColumnName(str);
        if (fieldTypeVerifyColumnName.isForeignCollection()) {
            throw new SQLException(AbstractC0147y.d("Can't update foreign colletion field: ", str));
        }
        addUpdateColumnToList(str, new SetExpression(str, fieldTypeVerifyColumnName, str2));
        return this;
    }

    public UpdateBuilder<T, ID> updateColumnValue(String str, Object obj) throws SQLException {
        FieldType fieldTypeVerifyColumnName = verifyColumnName(str);
        if (fieldTypeVerifyColumnName.isForeignCollection()) {
            throw new SQLException(AbstractC0147y.d("Can't update foreign colletion field: ", str));
        }
        addUpdateColumnToList(str, new SetValue(str, fieldTypeVerifyColumnName, obj));
        return this;
    }

    public String escapeColumnName(String str) {
        StringBuilder sb = new StringBuilder(str.length() + 4);
        this.databaseType.appendEscapedEntityName(sb, str);
        return sb.toString();
    }

    public String escapeValue(String str) {
        StringBuilder sb = new StringBuilder(str.length() + 4);
        this.databaseType.appendEscapedWord(sb, str);
        return sb.toString();
    }
}
