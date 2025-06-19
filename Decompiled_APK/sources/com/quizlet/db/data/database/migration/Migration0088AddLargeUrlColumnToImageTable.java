package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.quizlet.android.migrator.a;
import com.quizlet.android.migrator.migrations.e;
import com.quizlet.android.migrator.tools.c;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.fields.DBImageFields;
import java.sql.SQLException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class Migration0088AddLargeUrlColumnToImageTable extends e {
    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) throws SQLException {
        c t = (c) abstractC0772a;
        Intrinsics.checkNotNullParameter(t, "t");
        t.o(DBImage.class, "image", DBImageFields.Names.SQUARE_URL, a.c);
        t.q(DBImageFields.Names.SMALL_URL, DBImageFields.Names.SQUARE_URL);
        t.q(DBImageFields.Names.MEDIUM_URL, DBImageFields.Names.SMALL_URL);
        t.q(DBImageFields.Names.LARGE_URL, DBImageFields.Names.MEDIUM_URL);
    }
}
