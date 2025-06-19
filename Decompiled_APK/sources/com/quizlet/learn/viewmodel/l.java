package com.quizlet.learn.viewmodel;

import com.quizlet.ads.data.AdDataType;
import com.quizlet.data.model.C4116c1;
import com.quizlet.data.model.C4127f1;
import com.quizlet.data.model.I0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ G b;

    public /* synthetic */ l(G g, int i) {
        this.a = i;
        this.b = g;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                I0 progressReset = (I0) obj;
                Intrinsics.checkNotNullParameter(progressReset, "progressReset");
                progressReset.getClass();
                this.b.o1 = (C4127f1) (progressReset instanceof C4116c1 ? ((C4116c1) progressReset).a : null);
                break;
            case 1:
                AdDataType it2 = (AdDataType) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.M.j(new com.quizlet.learn.data.B(it2));
                break;
            default:
                Throwable p0 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                G.C(this.b, p0);
                break;
        }
    }
}
