package com.quizlet.quizletandroid.ui.setcreation.managers;

import com.google.android.gms.internal.ads.Zh;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l implements com.quizlet.infra.legacysyncengine.datasources.b {
    public final /* synthetic */ int a;
    public final Zh b;

    public l(Zh modelsManager, int i) {
        this.a = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(modelsManager, "modelsManager");
                this.b = modelsManager;
                break;
            default:
                Intrinsics.checkNotNullParameter(modelsManager, "modelsManager");
                this.b = modelsManager;
                break;
        }
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.b
    public final void h(List list) {
        switch (this.a) {
            case 0:
                if (list.isEmpty()) {
                    return;
                }
                DBStudySet dBStudySet = (DBStudySet) list.get(0);
                Zh zh = this.b;
                zh.i = dBStudySet;
                ((io.reactivex.rxjava3.subjects.r) zh.o).onSuccess(dBStudySet);
                zh.a().a(this);
                return;
            default:
                Zh zh2 = this.b;
                zh2.getClass();
                Intrinsics.checkNotNullParameter(list, "<set-?>");
                zh2.n = list;
                io.reactivex.rxjava3.subjects.r rVar = (io.reactivex.rxjava3.subjects.r) zh2.p;
                int i = 0;
                if (!list.isEmpty()) {
                    Iterator it2 = list.iterator();
                    while (it2.hasNext()) {
                        if (((DBTerm) it2.next()).hasValidUserContent() && (i = i + 1) < 0) {
                            B.o();
                            throw null;
                        }
                    }
                }
                rVar.onSuccess(Integer.valueOf(i + 1));
                return;
        }
    }
}
