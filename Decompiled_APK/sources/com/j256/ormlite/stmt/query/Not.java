package com.j256.ormlite.stmt.query;

import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.stmt.ArgumentHolder;
import java.sql.SQLException;
import java.util.List;

/* loaded from: classes2.dex */
public class Not implements Clause, NeedsFutureClause {
    private Comparison comparison = null;
    private Exists exists = null;

    public Not() {
    }

    @Override // com.j256.ormlite.stmt.query.Clause
    public void appendSql(DatabaseType databaseType, String str, StringBuilder sb, List<ArgumentHolder> list, Clause clause) throws SQLException {
        StringBuilder sb2;
        if (this.comparison == null && this.exists == null) {
            throw new IllegalStateException("Clause has not been set in NOT operation");
        }
        sb.append("(NOT ");
        if (this.comparison == null) {
            sb2 = sb;
            this.exists.appendSql(databaseType, str, sb2, list, clause);
        } else {
            sb2 = sb;
            if (str != null) {
                databaseType.appendEscapedEntityName(sb2, str);
                sb2.append('.');
            }
            databaseType.appendEscapedEntityName(sb2, this.comparison.getColumnName());
            sb2.append(' ');
            this.comparison.appendOperation(sb2);
            this.comparison.appendValue(databaseType, sb2, list);
        }
        int length = sb2.length();
        if (length > 0) {
            int i = length - 1;
            if (sb2.charAt(i) == ' ') {
                sb2.setLength(i);
            }
        }
        sb2.append(") ");
    }

    @Override // com.j256.ormlite.stmt.query.NeedsFutureClause
    public void setMissingClause(Clause clause) {
        if (this.comparison != null) {
            throw new IllegalArgumentException("NOT operation already has a comparison set");
        }
        if (clause instanceof Comparison) {
            this.comparison = (Comparison) clause;
        } else if (clause instanceof Exists) {
            this.exists = (Exists) clause;
        } else {
            throw new IllegalArgumentException("NOT operation can only work with comparison SQL clauses, not " + clause);
        }
    }

    public String toString() {
        if (this.comparison == null) {
            return "NOT without comparison";
        }
        return "NOT comparison " + this.comparison;
    }

    public Not(Clause clause) {
        setMissingClause(clause);
    }
}
