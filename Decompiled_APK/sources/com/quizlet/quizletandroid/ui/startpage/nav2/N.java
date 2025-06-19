package com.quizlet.quizletandroid.ui.startpage.nav2;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class N implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Y b;

    public /* synthetic */ N(Y y, int i) {
        this.a = i;
        this.b = y;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.disposables.b it2 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.G.j(Boolean.TRUE);
                break;
            default:
                List it3 = (List) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                this.b.G.j(Boolean.FALSE);
                break;
        }
    }
}
