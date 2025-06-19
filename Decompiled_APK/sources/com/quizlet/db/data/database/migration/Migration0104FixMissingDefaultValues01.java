package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.quizlet.android.migrator.migrations.d;
import com.quizlet.android.migrator.tools.b;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class Migration0104FixMissingDefaultValues01 extends d {
    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) {
        b dataTools = (b) abstractC0772a;
        Intrinsics.checkNotNullParameter(dataTools, "dataTools");
        dataTools.o(DBUser.class, "user", DBUserFields.Names.IS_SELF_LEARNER, "0", "isSelfLearner IS NULL");
        dataTools.o(DBStudySet.class, "set", DBStudySetFields.Names.MCQ_COUNT, "0", "mcqCount IS NULL");
        dataTools.o(DBUser.class, "user", DBUserFields.Names.HAS_OPTED_IN_FOR_OFFLINE_PROMO, "0", "hasOptedInForOfflinePromo IS NULL");
    }
}
