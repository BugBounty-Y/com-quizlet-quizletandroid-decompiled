package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.quizlet.android.migrator.a;
import com.quizlet.android.migrator.migrations.e;
import com.quizlet.android.migrator.tools.c;
import com.quizlet.db.data.models.persisted.DBStudySetting;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.sql.SQLException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class Migration0081AddClientTimestampFieldForStudySettingIfMissing extends e {

    @NotNull
    private static final Class<DBStudySetting> modelClass = DBStudySetting.class;

    @Metadata
    public static final class Companion {
        @NotNull
        public final Class<DBStudySetting> getModelClass() {
            return Migration0081AddClientTimestampFieldForStudySettingIfMissing.modelClass;
        }
    }

    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) {
        c schemaTools = (c) abstractC0772a;
        Intrinsics.checkNotNullParameter(schemaTools, "schemaTools");
        try {
            schemaTools.o(modelClass, DBStudySetting.TABLE_NAME, BaseDBModelFields.Names.CLIENT_TIMESTAMP, a.b);
            timber.log.c.a.g("Successfully added missing clientTimestamp column to study_setting table", new Object[0]);
        } catch (SQLException e) {
            timber.log.c.a.i(e, "User already had clientTimestamp column for study_setting", new Object[0]);
        }
    }
}
