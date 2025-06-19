package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.quizlet.android.migrator.a;
import com.quizlet.android.migrator.migrations.e;
import com.quizlet.android.migrator.tools.c;
import com.quizlet.db.data.models.persisted.DBGroup;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public class Migration0076AddCreatorIdToDBGroupTable extends e {
    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) throws SQLException {
        ((c) abstractC0772a).o(DBGroup.class, DBGroup.TABLE_NAME, "creatorId", a.b);
    }
}
