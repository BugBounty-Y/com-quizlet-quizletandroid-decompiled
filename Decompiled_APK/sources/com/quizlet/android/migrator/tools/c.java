package com.quizlet.android.migrator.tools;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.runtime.AbstractC0772a;
import com.google.firebase.messaging.p;
import com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper;
import com.j256.ormlite.support.ConnectionSource;
import com.quizlet.db.data.models.persisted.DBImage;
import java.sql.SQLException;
import java.util.LinkedHashSet;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends AbstractC0772a {
    public final SQLiteDatabase d;

    public c(SQLiteDatabase sQLiteDatabase, OrmLiteSqliteOpenHelper ormLiteSqliteOpenHelper, ConnectionSource connectionSource, p pVar) {
        super(ormLiteSqliteOpenHelper, connectionSource, pVar);
        this.d = sQLiteDatabase;
    }

    public final void o(Class cls, String str, String str2, com.quizlet.android.migrator.a aVar) throws SQLException {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        int iOrdinal = aVar.ordinal();
        String str3 = "0";
        if (iOrdinal != 0 && iOrdinal != 1) {
            if (iOrdinal == 2) {
                str3 = null;
            } else if (iOrdinal != 3) {
                throw new NoWhenBranchMatchedException();
            }
        }
        p(cls, str, str2, aVar, str3);
    }

    public final void p(Class cls, String tableName, String fieldName, com.quizlet.android.migrator.a dataType, String str) throws SQLException {
        if (((LinkedHashSet) ((p) this.c).b).contains(tableName)) {
            Intrinsics.checkNotNullParameter(tableName, "tableName");
            Intrinsics.checkNotNullParameter(fieldName, "fieldName");
            Intrinsics.checkNotNullParameter(dataType, "dataType");
            String strG = AbstractC0147y.g(AbstractC0147y.h("ALTER TABLE `", tableName, "` ADD COLUMN ", fieldName, " "), dataType.name(), str != null ? android.support.v4.media.session.a.B(" DEFAULT `", str, "`") : "", ";");
            timber.log.c.a.a(strG, new Object[0]);
            ((OrmLiteSqliteOpenHelper) this.a).getDao(cls).executeRawNoArgs(strG);
        }
    }

    public final void q(String str, String str2) throws SQLException {
        if (((LinkedHashSet) ((p) this.c).b).contains("image")) {
            String strE = AbstractC0147y.e("UPDATE `image` SET ", str2, " = ", str, ";");
            timber.log.c.a.a(strE, new Object[0]);
            ((OrmLiteSqliteOpenHelper) this.a).getDao(DBImage.class).executeRawNoArgs(strE);
        }
    }

    public final boolean r(String str) {
        Cursor cursorRawQuery;
        boolean zEquals = false;
        if (!((LinkedHashSet) ((p) this.c).b).contains("user") || (cursorRawQuery = this.d.rawQuery("PRAGMA table_info(user)", null)) == null) {
            return false;
        }
        int columnIndex = cursorRawQuery.getColumnIndex("name");
        if (columnIndex != -1 && cursorRawQuery.moveToFirst()) {
            do {
                zEquals = cursorRawQuery.getString(columnIndex).equals(str);
                if (zEquals) {
                    break;
                }
            } while (cursorRawQuery.moveToNext());
        }
        cursorRawQuery.close();
        return zEquals;
    }
}
