package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.quizlet.android.migrator.migrations.d;
import com.quizlet.android.migrator.tools.b;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class Migration0080SetClientTimestampForAllDBModels extends d {
    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) {
        b dataTools = (b) abstractC0772a;
        Intrinsics.checkNotNullParameter(dataTools, "dataTools");
        long jCurrentTimeMillis = System.currentTimeMillis() / 1000;
        for (Map.Entry<Class<? extends BaseDBModel>, String> entry : Migration0079AddClientTimestampToAllDBModels.b.getTables().entrySet()) {
            dataTools.o(entry.getKey(), entry.getValue(), BaseDBModelFields.Names.CLIENT_TIMESTAMP, String.valueOf(jCurrentTimeMillis), null);
        }
    }
}
