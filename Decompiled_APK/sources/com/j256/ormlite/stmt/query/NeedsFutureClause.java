package com.j256.ormlite.stmt.query;

import com.j256.ormlite.db.DatabaseType;
import java.sql.SQLException;
import java.util.List;

/* loaded from: classes2.dex */
public interface NeedsFutureClause extends Clause {
    @Override // com.j256.ormlite.stmt.query.Clause
    /* synthetic */ void appendSql(DatabaseType databaseType, String str, StringBuilder sb, List list, Clause clause) throws SQLException;

    void setMissingClause(Clause clause);
}
