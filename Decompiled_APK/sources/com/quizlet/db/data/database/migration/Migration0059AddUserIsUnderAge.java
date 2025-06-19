package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.quizlet.android.migrator.a;
import com.quizlet.android.migrator.migrations.e;
import com.quizlet.android.migrator.tools.c;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public class Migration0059AddUserIsUnderAge extends e {
    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) throws SQLException {
        ((c) abstractC0772a).o(DBUser.class, "user", DBUserFields.Names.IS_UNDER_AGE, a.d);
    }
}
