package com.quizlet.features.setpage.viewmodel;

import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.setpage.screenstates.C4423c;
import com.quizlet.quizletandroid.R;
import com.quizlet.utm.a;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.setpage.viewmodel.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4435i implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ P b;

    public /* synthetic */ C4435i(P p, int i) {
        this.a = i;
        this.b = p;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter((io.reactivex.rxjava3.disposables.b) obj, "it");
                this.b.e1.j(com.quizlet.features.setpage.screenstates.n.a);
                return;
            case 1:
                DBStudySet it2 = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.i1.l(new com.quizlet.features.infra.basestudy.data.models.b(it2.getId()));
                return;
            case 2:
                Throwable it3 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                this.b.j1.l(new C4423c(R.string.copy_set_generic_error));
                timber.log.c.a.e(it3);
                return;
            case 3:
                DBStudySet set = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(set, "set");
                ((EventLogger) this.b.f.b).K(set.getId(), set.getLocalId(), 1);
                return;
            default:
                com.quizlet.features.infra.basestudy.data.models.shareset.a shareStatus = (com.quizlet.features.infra.basestudy.data.models.shareset.a) obj;
                Intrinsics.checkNotNullParameter(shareStatus, "shareStatus");
                P p = this.b;
                if (p.G()) {
                    DBStudySet dBStudySet = p.F1;
                    if (dBStudySet == null) {
                        Intrinsics.m("set");
                        throw null;
                    }
                    String title = dBStudySet.getTitle();
                    if (title == null) {
                        return;
                    }
                    C4437k c4437k = new C4437k(3);
                    if (shareStatus == com.quizlet.features.infra.basestudy.data.models.shareset.a.d) {
                        DBStudySet dBStudySet2 = p.F1;
                        if (dBStudySet2 == null) {
                            Intrinsics.m("set");
                            throw null;
                        }
                        int i = dBStudySet2.getAccessType() == 2 ? R.string.cannot_share_own_underage_set : R.string.cannot_share_private_set;
                        Object[] args = new Object[0];
                        Intrinsics.checkNotNullParameter(args, "args");
                        p.p1.l(new com.quizlet.features.infra.snackbar.m(new com.quizlet.qutils.string.f(i, C4933y.P(args))));
                        return;
                    }
                    long jD = p.D();
                    DBStudySet dBStudySet3 = p.F1;
                    if (dBStudySet3 == null) {
                        Intrinsics.m("set");
                        throw null;
                    }
                    String webUrl = dBStudySet3.getWebUrl();
                    a.C0023a c0023a = new a.C0023a(new a.c(com.quizlet.utm.campaigns.b.SET_PAGE_SHARE, com.quizlet.utm.mediums.b.SHARE_LINK, com.quizlet.utm.sources.b.SHARE_SHEET_ANDROID), Long.valueOf(p.k.getPersonId()));
                    DBStudySet dBStudySet4 = p.F1;
                    if (dBStudySet4 == null) {
                        Intrinsics.m("set");
                        throw null;
                    }
                    p.Z.l(new com.quizlet.features.setpage.screenstates.z(jD, webUrl, title, c0023a, p.e, c4437k, shareStatus, dBStudySet4.getAccessType()));
                    p.g.g();
                    return;
                }
                return;
        }
    }
}
