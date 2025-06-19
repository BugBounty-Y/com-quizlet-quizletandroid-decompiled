package com.quizlet.android.migrator.migrations;

import android.util.Log;
import androidx.compose.runtime.AbstractC0772a;
import com.google.firebase.messaging.p;
import com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper;
import com.quizlet.android.migrator.MigrationState$TableDoesNotExistException;
import com.quizlet.db.data.models.persisted.DBStudySet;
import java.sql.SQLException;
import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class b extends a {
    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) throws SQLException {
        Throwable cause;
        String message;
        com.quizlet.android.migrator.tools.a aVar = (com.quizlet.android.migrator.tools.a) abstractC0772a;
        com.quizlet.android.migrator.migrations.changes.c change = getChange();
        switch (aVar.d) {
            case 0:
                com.quizlet.android.migrator.migrations.changes.a aVar2 = (com.quizlet.android.migrator.migrations.changes.a) change;
                ((OrmLiteSqliteOpenHelper) aVar.a).getDao(aVar2.a).executeRawNoArgs(aVar2.c);
                return;
            default:
                com.quizlet.android.migrator.migrations.changes.b change2 = (com.quizlet.android.migrator.migrations.changes.b) change;
                Intrinsics.checkNotNullParameter(change2, "change");
                try {
                    ((OrmLiteSqliteOpenHelper) aVar.a).getDao(DBStudySet.class).executeRawNoArgs(android.support.v4.media.session.a.B("DROP TABLE `", change2.a, "`"));
                    return;
                } catch (SQLException e) {
                    Throwable cause2 = e.getCause();
                    if (cause2 == null || (cause = cause2.getCause()) == null || (message = cause.getMessage()) == null || !StringsKt.G(message, "no such table", false)) {
                        throw e;
                    }
                    Log.w("DropTableTools", "Table '" + change2.a + "' does not exist, ignoring");
                    return;
                }
        }
    }

    @Override // com.quizlet.android.migrator.migrations.a
    public final void c(AbstractC0772a abstractC0772a) {
        com.quizlet.android.migrator.tools.a aVar = (com.quizlet.android.migrator.tools.a) abstractC0772a;
        com.quizlet.android.migrator.migrations.changes.c change = getChange();
        switch (aVar.d) {
            case 0:
                String str = ((com.quizlet.android.migrator.migrations.changes.a) change).b;
                LinkedHashSet linkedHashSet = (LinkedHashSet) ((p) aVar.c).b;
                if (linkedHashSet.contains(str)) {
                    throw new RuntimeException(android.support.v4.media.session.a.B("Table ", str, " already exists"));
                }
                linkedHashSet.add(str);
                return;
            default:
                com.quizlet.android.migrator.migrations.changes.b change2 = (com.quizlet.android.migrator.migrations.changes.b) change;
                Intrinsics.checkNotNullParameter(change2, "change");
                try {
                    p pVar = (p) aVar.c;
                    String str2 = change2.a;
                    LinkedHashSet linkedHashSet2 = (LinkedHashSet) pVar.b;
                    if (linkedHashSet2.contains(str2)) {
                        linkedHashSet2.remove(str2);
                        return;
                    }
                    throw new MigrationState$TableDoesNotExistException("Table " + str2 + " does not exist");
                } catch (MigrationState$TableDoesNotExistException unused) {
                    Log.w("DropTableTools", "Table '" + change2.a + "' does not exist, ignoring");
                    return;
                }
        }
    }

    public abstract com.quizlet.android.migrator.migrations.changes.c getChange();

    @Override // com.quizlet.android.migrator.migrations.a
    public Integer getVersion() {
        return Integer.valueOf(this.a);
    }
}
