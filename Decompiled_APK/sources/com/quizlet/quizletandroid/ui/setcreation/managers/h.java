package com.quizlet.quizletandroid.ui.setcreation.managers;

import com.quizlet.db.data.models.persisted.DBStudySet;
import java.util.List;

/* loaded from: classes3.dex */
public final class h implements com.quizlet.infra.legacysyncengine.datasources.b {
    public final /* synthetic */ int a;
    public final i b;

    public /* synthetic */ h(i iVar, int i) {
        this.a = i;
        this.b = iVar;
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.b
    public final void h(List list) {
        switch (this.a) {
            case 0:
                if (!list.isEmpty()) {
                    int size = list.size();
                    i iVar = this.b;
                    if (size > 1) {
                        timber.log.c.b(new IllegalStateException("We received an update about sets and were informed of more than one set. This is odd. We see " + list.size() + " for " + iVar.k));
                    }
                    if (!iVar.o.s() && !iVar.o.r()) {
                        DBStudySet dBStudySet = (DBStudySet) list.get(0);
                        iVar.m = dBStudySet;
                        iVar.o.onSuccess(dBStudySet);
                        iVar.n.a(this);
                        break;
                    } else {
                        timber.log.c.b(new IllegalStateException("Attempting to update Study Set data a second time"));
                        break;
                    }
                }
                break;
            default:
                i iVar2 = this.b;
                if (!iVar2.q.s()) {
                    if (!iVar2.q.r()) {
                        iVar2.q.onSuccess(list);
                        iVar2.r.a(this);
                        break;
                    } else {
                        io.reactivex.rxjava3.subjects.r rVar = iVar2.q;
                        timber.log.c.a.q(rVar.a.get() == io.reactivex.rxjava3.subjects.r.f ? rVar.d : null, "Error occurred while trying to update Term", new Object[0]);
                        break;
                    }
                } else {
                    timber.log.c.b(new IllegalStateException("Attempting to update Term data a second time"));
                    break;
                }
        }
    }
}
