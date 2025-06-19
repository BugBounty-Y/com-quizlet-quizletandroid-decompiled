package com.quizlet.db.data.database;

import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.measurement.internal.N;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import java.util.concurrent.Callable;
import kotlin.jvm.internal.Intrinsics;
import timber.log.c;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;

    public /* synthetic */ a(Object obj, long j, int i) {
        this.a = i;
        this.c = obj;
        this.b = j;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        long score = this.b;
        Object obj = this.c;
        switch (this.a) {
            case 0:
                int i = DatabaseHelper.a;
                DatabaseHelper databaseHelper = (DatabaseHelper) obj;
                databaseHelper.getClass();
                Object[] objArr = {Integer.valueOf(databaseHelper.i(Models.SELECTED_TERM).updateRaw("UPDATE `selected_term` SET personId = ? WHERE personId = 0 OR personId IS NULL;", Long.toString(score))), Long.valueOf(score)};
                timber.log.a aVar = c.a;
                aVar.a("Assigned %s selected terms to user %s", objArr);
                aVar.a("Assigned %s session to user %s", Integer.valueOf(databaseHelper.i(Models.SESSION).updateRaw("UPDATE `session` SET personId = ? WHERE personId = 0 OR personId IS NULL;", Long.toString(score))), Long.valueOf(score));
                aVar.a("Assigned %s answers to user %s", Integer.valueOf(databaseHelper.i(Models.ANSWER).updateRaw("UPDATE `answer` SET personId = ? WHERE personId = 0 OR personId IS NULL;", Long.toString(score))), Long.valueOf(score));
                aVar.a("Assigned %s study settings to user %s", Integer.valueOf(databaseHelper.i(Models.STUDY_SETTING).updateRaw("UPDATE `study_setting` SET personId = ? WHERE personId = 0 OR personId IS NULL;", Long.toString(score))), Long.valueOf(score));
                return null;
            default:
                s sVar = (s) obj;
                N n = (N) sVar.b;
                DatabaseHelper databaseHelper2 = (DatabaseHelper) sVar.a;
                Intrinsics.checkNotNullParameter(databaseHelper2, "databaseHelper");
                DBSession dBSession = (DBSession) databaseHelper2.i(Models.SESSION).queryBuilder().orderBy(DBSessionFields.Names.SCORE, true).where().eq(DBSessionFields.STUDYABLE.getDatabaseColumnName(), Long.valueOf(n.c)).and().eq(DBSessionFields.ITEM_TYPE.getDatabaseColumnName(), Integer.valueOf(((G1) n.e).b())).and().eq(DBSessionFields.Names.SELECTED_TERMS_ONLY, Boolean.valueOf(n.b)).and().eq(DBSessionFields.MODE_TYPE.getDatabaseColumnName(), Integer.valueOf(((A1) n.d).a())).and().gt(DBSessionFields.Names.SCORE, 0).queryForFirst();
                if (dBSession != null) {
                    score = score < 0 ? dBSession.getScore() : Math.min(score, dBSession.getScore());
                }
                return Long.valueOf(score);
        }
    }
}
