package com.quizlet.quizletandroid.ui.setcreation.managers;

import com.google.android.gms.internal.ads.Zh;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.scandocument.model.y;
import java.util.List;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Zh b;

    public /* synthetic */ m(Zh zh, int i) {
        this.a = i;
        this.b = zh;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        Zh zh = this.b;
        switch (this.a) {
            case 0:
                DBStudySet dBStudySet = (DBStudySet) obj;
                Intrinsics.d(dBStudySet);
                zh.getClass();
                dBStudySet.setDeleted(true);
                DBModel[] dBModelArr = {dBStudySet};
                com.quizlet.infra.legacysyncengine.managers.i iVar = (com.quizlet.infra.legacysyncengine.managers.i) zh.f;
                iVar.c(dBModelArr);
                for (DBTerm dBTerm : (List) zh.n) {
                    dBTerm.setDeleted(true);
                    DBImage definitionImage = dBTerm.getDefinitionImage();
                    if (definitionImage != null && !definitionImage.getIdentity().hasServerIdentity()) {
                        definitionImage.setDeleted(true);
                        iVar.c(definitionImage);
                    }
                    iVar.c(dBTerm);
                }
                DBStudySet dBStudySet2 = (DBStudySet) zh.i;
                ((ExecutionRouter) zh.d).e(new com.google.firebase.crashlytics.internal.common.i(25, zh, dBStudySet2 != null ? Long.valueOf(dBStudySet2.getId()) : new IllegalStateException("Study Set must be initialized before deleting!")));
                break;
            case 1:
                DBStudySet dBStudySet3 = (DBStudySet) obj;
                ((io.reactivex.rxjava3.subjects.d) zh.q).b(new y(dBStudySet3.getId(), dBStudySet3.getLocalId(), ((List) zh.n).size()));
                break;
            case 2:
                Throwable e = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e, "e");
                ((io.reactivex.rxjava3.subjects.d) zh.q).b(new com.quizlet.scandocument.model.r(new IllegalStateException("Received an error while trying to publish set", e)));
                break;
            default:
                ((p) zh.h).a.edit().putLong(String.valueOf(((DBStudySet) obj).getLocalId()), TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis())).apply();
                break;
        }
    }
}
