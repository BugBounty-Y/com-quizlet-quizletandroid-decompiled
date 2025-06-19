package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.quizlet.android.migrator.migrations.d;
import com.quizlet.android.migrator.tools.b;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;

/* loaded from: classes2.dex */
public class Migration0065PopulateAnswerCorrectnessColumn extends d {
    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) {
        b bVar = (b) abstractC0772a;
        bVar.o(DBAnswer.class, "answer", DBAnswerFields.Names.CORRECTNESS, "0", "isCorrect = 0");
        bVar.o(DBAnswer.class, "answer", DBAnswerFields.Names.CORRECTNESS, "1", "isCorrect = 1");
    }
}
