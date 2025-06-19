package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.quizlet.android.migrator.migrations.d;
import com.quizlet.android.migrator.tools.b;
import com.quizlet.db.data.models.persisted.DBAnswer;

/* loaded from: classes2.dex */
public class Migration0051AssignPersonIdToAnswers extends d {
    public final long b;

    public Migration0051AssignPersonIdToAnswers(long j) {
        super(51);
        this.b = j;
    }

    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) {
        b bVar = (b) abstractC0772a;
        long j = this.b;
        if (j > 0) {
            bVar.o(DBAnswer.class, "answer", "personId", Long.toString(j), "personId = 0");
        }
        bVar.o(DBAnswer.class, "answer", "dirty", Integer.toString(1), null);
    }
}
