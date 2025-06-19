package com.j256.ormlite.stmt;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.stmt.StatementBuilder;
import com.j256.ormlite.table.TableInfo;
import java.sql.SQLException;
import java.util.List;

/* loaded from: classes2.dex */
public class DeleteBuilder<T, ID> extends StatementBuilder<T, ID> {
    private Long limit;

    public DeleteBuilder(DatabaseType databaseType, TableInfo<T, ID> tableInfo, Dao<T, ID> dao) {
        super(databaseType, tableInfo, dao, StatementBuilder.StatementType.DELETE);
    }

    private void appendLimit(StringBuilder sb) {
        Long l = this.limit;
        if (l != null) {
            this.databaseType.appendUpdateLimitValue(sb, l.longValue());
        }
    }

    @Override // com.j256.ormlite.stmt.StatementBuilder
    public void appendStatementEnd(StringBuilder sb, List<ArgumentHolder> list) {
        if (this.databaseType.isLimitDeleteAtEndSupported()) {
            appendLimit(sb);
        }
    }

    @Override // com.j256.ormlite.stmt.StatementBuilder
    public void appendStatementStart(StringBuilder sb, List<ArgumentHolder> list) {
        sb.append("DELETE FROM ");
        if (this.tableInfo.getSchemaName() != null && this.tableInfo.getSchemaName().length() > 0) {
            this.databaseType.appendEscapedEntityName(sb, this.tableInfo.getSchemaName());
            sb.append('.');
        }
        if (this.databaseType.isLimitAfterDeleteSupported()) {
            appendLimit(sb);
        }
        this.databaseType.appendEscapedEntityName(sb, this.tableInfo.getTableName());
        sb.append(' ');
    }

    public int delete() throws SQLException {
        return this.dao.delete((PreparedDelete) prepare());
    }

    public DeleteBuilder<T, ID> limit(Long l) {
        this.limit = l;
        return this;
    }

    public PreparedDelete<T> prepare() throws SQLException {
        return super.prepareStatement(this.limit, false);
    }

    @Override // com.j256.ormlite.stmt.StatementBuilder
    public void reset() {
        super.reset();
        this.limit = null;
    }
}
