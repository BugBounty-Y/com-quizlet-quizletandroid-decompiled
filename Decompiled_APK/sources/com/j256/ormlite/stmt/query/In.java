package com.j256.ormlite.stmt.query;

import android.support.v4.media.session.a;
import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.stmt.ArgumentHolder;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;

/* loaded from: classes2.dex */
public class In extends BaseComparison {
    private final boolean in;
    private Iterable<?> objects;

    public In(String str, FieldType fieldType, Iterable<?> iterable, boolean z) throws SQLException {
        super(str, fieldType, null, true);
        this.objects = iterable;
        this.in = z;
    }

    @Override // com.j256.ormlite.stmt.query.BaseComparison, com.j256.ormlite.stmt.query.Comparison
    public void appendOperation(StringBuilder sb) {
        if (this.in) {
            sb.append("IN ");
        } else {
            sb.append("NOT IN ");
        }
    }

    @Override // com.j256.ormlite.stmt.query.BaseComparison, com.j256.ormlite.stmt.query.Comparison, com.j256.ormlite.stmt.query.Clause
    public /* bridge */ /* synthetic */ void appendSql(DatabaseType databaseType, String str, StringBuilder sb, List list, Clause clause) throws SQLException {
        super.appendSql(databaseType, str, sb, list, clause);
    }

    @Override // com.j256.ormlite.stmt.query.BaseComparison, com.j256.ormlite.stmt.query.Comparison
    public void appendValue(DatabaseType databaseType, StringBuilder sb, List<ArgumentHolder> list) throws SQLException {
        sb.append('(');
        boolean z = true;
        for (Object obj : this.objects) {
            if (obj == null) {
                throw new IllegalArgumentException(a.t(new StringBuilder("one of the IN values for '"), this.columnName, "' is null"));
            }
            if (z) {
                z = false;
            } else {
                sb.append(", ");
            }
            DatabaseType databaseType2 = databaseType;
            StringBuilder sb2 = sb;
            List<ArgumentHolder> list2 = list;
            super.appendArgOrValue(databaseType2, this.fieldType, sb2, list2, obj);
            int length = sb2.length();
            if (length > 0) {
                int i = length - 1;
                if (sb2.charAt(i) == ' ') {
                    sb2.setLength(i);
                }
            }
            databaseType = databaseType2;
            sb = sb2;
            list = list2;
        }
        sb.append(") ");
    }

    @Override // com.j256.ormlite.stmt.query.BaseComparison, com.j256.ormlite.stmt.query.Comparison
    public /* bridge */ /* synthetic */ String getColumnName() {
        return super.getColumnName();
    }

    @Override // com.j256.ormlite.stmt.query.BaseComparison
    public /* bridge */ /* synthetic */ String toString() {
        return super.toString();
    }

    public In(String str, FieldType fieldType, Object[] objArr, boolean z) throws SQLException {
        super(str, fieldType, null, true);
        this.objects = Arrays.asList(objArr);
        this.in = z;
    }
}
