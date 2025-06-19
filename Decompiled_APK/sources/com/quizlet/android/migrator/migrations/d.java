package com.quizlet.android.migrator.migrations;

import androidx.compose.runtime.AbstractC0772a;
import com.google.firebase.messaging.p;
import com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper;
import com.j256.ormlite.support.ConnectionSource;

/* loaded from: classes2.dex */
public abstract class d extends a {
    @Override // com.quizlet.android.migrator.migrations.a
    public final AbstractC0772a a(com.quizlet.data.interactor.progress.c cVar) {
        return new com.quizlet.android.migrator.tools.b((OrmLiteSqliteOpenHelper) cVar.b, (ConnectionSource) cVar.c, (p) cVar.d);
    }

    @Override // com.quizlet.android.migrator.migrations.a
    public final /* bridge */ /* synthetic */ void c(AbstractC0772a abstractC0772a) {
    }

    @Override // com.quizlet.android.migrator.migrations.a
    public Integer getVersion() {
        return Integer.valueOf(this.a);
    }
}
