package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.quizlet.android.migrator.a;
import com.quizlet.android.migrator.migrations.e;
import com.quizlet.android.migrator.tools.c;
import com.quizlet.db.data.models.persisted.DBUser;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public class Migration0053AddLocaleColumnsToUser extends e {
    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) throws SQLException {
        c cVar = (c) abstractC0772a;
        boolean zR = cVar.r("mobileLocale");
        a aVar = a.c;
        if (!zR) {
            cVar.o(DBUser.class, "user", "mobileLocale", aVar);
        }
        if (cVar.r("userLocalePreference")) {
            return;
        }
        cVar.o(DBUser.class, "user", "userLocalePreference", aVar);
    }
}
