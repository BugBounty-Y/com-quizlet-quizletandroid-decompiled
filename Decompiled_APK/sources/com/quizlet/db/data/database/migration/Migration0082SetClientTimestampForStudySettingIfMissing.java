package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.quizlet.android.migrator.migrations.d;
import com.quizlet.android.migrator.tools.b;
import com.quizlet.db.data.models.persisted.DBStudySetting;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class Migration0082SetClientTimestampForStudySettingIfMissing extends d {

    @NotNull
    private static final Class<DBStudySetting> modelClass = DBStudySetting.class;

    @Metadata
    public static final class Companion {
        @NotNull
        public final Class<DBStudySetting> getModelClass() {
            return Migration0082SetClientTimestampForStudySettingIfMissing.modelClass;
        }
    }

    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) {
        b dataTools = (b) abstractC0772a;
        Intrinsics.checkNotNullParameter(dataTools, "dataTools");
        dataTools.o(modelClass, DBStudySetting.TABLE_NAME, BaseDBModelFields.Names.CLIENT_TIMESTAMP, String.valueOf(System.currentTimeMillis() / 1000), "clientTimestamp = 0");
    }
}
