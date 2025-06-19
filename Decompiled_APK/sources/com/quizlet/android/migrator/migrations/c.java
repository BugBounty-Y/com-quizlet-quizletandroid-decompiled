package com.quizlet.android.migrator.migrations;

import androidx.compose.runtime.AbstractC0772a;
import com.google.firebase.messaging.p;
import com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper;
import com.j256.ormlite.support.ConnectionSource;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class c extends b {
    public final /* synthetic */ int b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(int i, int i2) {
        super(i);
        this.b = i2;
    }

    @Override // com.quizlet.android.migrator.migrations.a
    public final AbstractC0772a a(com.quizlet.data.interactor.progress.c cVar) {
        switch (this.b) {
            case 0:
                return new com.quizlet.android.migrator.tools.a((OrmLiteSqliteOpenHelper) cVar.b, (ConnectionSource) cVar.c, (p) cVar.d, 0);
            default:
                OrmLiteSqliteOpenHelper databaseHelper = (OrmLiteSqliteOpenHelper) cVar.b;
                Intrinsics.checkNotNullParameter(databaseHelper, "databaseHelper");
                ConnectionSource connectionSource = (ConnectionSource) cVar.c;
                Intrinsics.checkNotNullParameter(connectionSource, "connectionSource");
                p migrationState = (p) cVar.d;
                Intrinsics.checkNotNullParameter(migrationState, "migrationState");
                return new com.quizlet.android.migrator.tools.a(databaseHelper, connectionSource, migrationState, 1);
        }
    }
}
