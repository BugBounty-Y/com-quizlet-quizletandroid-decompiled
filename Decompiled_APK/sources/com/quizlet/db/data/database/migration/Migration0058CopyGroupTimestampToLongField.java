package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.google.firebase.messaging.p;
import com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper;
import com.quizlet.android.migrator.migrations.d;
import com.quizlet.android.migrator.tools.b;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import java.util.LinkedHashSet;
import timber.log.c;

/* loaded from: classes2.dex */
public class Migration0058CopyGroupTimestampToLongField extends d {
    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) {
        b bVar = (b) abstractC0772a;
        if (((LinkedHashSet) ((p) bVar.c).b).contains(DBGroupSet.TABLE_NAME)) {
            c.a.a("%s (%d records updated)", "UPDATE `group_set` SET timestamp_long = timestamp;", Integer.valueOf(((OrmLiteSqliteOpenHelper) bVar.a).getDao(DBGroupSet.class).updateRaw("UPDATE `group_set` SET timestamp_long = timestamp;", new String[0])));
        }
    }
}
