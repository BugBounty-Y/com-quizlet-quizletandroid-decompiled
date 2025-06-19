package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper;
import com.quizlet.android.migrator.migrations.d;
import com.quizlet.android.migrator.tools.b;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public class Migration0050AddSessionItemIdAndItemType extends d {
    public OrmLiteSqliteOpenHelper b;

    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) throws SQLException {
        b bVar = (b) abstractC0772a;
        OrmLiteSqliteOpenHelper ormLiteSqliteOpenHelper = this.b;
        ormLiteSqliteOpenHelper.getDao(DBSession.class).executeRaw("ALTER TABLE `session` ADD COLUMN itemId LONG;", new String[0]);
        ormLiteSqliteOpenHelper.getDao(DBSession.class).executeRaw("ALTER TABLE `session` ADD COLUMN itemType INTEGER;", new String[0]);
        bVar.o(DBSession.class, "session", DBSessionFields.Names.ITEM_ID, "setId", null);
        bVar.o(DBSession.class, "session", DBSessionFields.Names.ITEM_TYPE, Integer.toString(1), null);
        bVar.o(DBSession.class, "session", "setId", "null", null);
    }
}
