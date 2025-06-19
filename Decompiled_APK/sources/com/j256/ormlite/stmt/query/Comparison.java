package com.j256.ormlite.stmt.query;

import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.stmt.ArgumentHolder;
import java.sql.SQLException;
import java.util.List;

/* loaded from: classes2.dex */
interface Comparison extends Clause {
    void appendOperation(StringBuilder sb);

    @Override // com.j256.ormlite.stmt.query.Clause
    /* synthetic */ void appendSql(DatabaseType databaseType, String str, StringBuilder sb, List list, Clause clause) throws SQLException;

    void appendValue(DatabaseType databaseType, StringBuilder sb, List<ArgumentHolder> list) throws SQLException;

    String getColumnName();
}
