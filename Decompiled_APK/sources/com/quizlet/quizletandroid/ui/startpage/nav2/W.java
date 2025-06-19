package com.quizlet.quizletandroid.ui.startpage.nav2;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class W implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.lifecycle.Y b;

    public /* synthetic */ W(androidx.lifecycle.Y y, int i) {
        this.a = i;
        this.b = y;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object it2) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter((io.reactivex.rxjava3.disposables.b) it2, "it");
                this.b.j(Boolean.TRUE);
                break;
            case 1:
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.j(Boolean.FALSE);
                break;
            case 2:
                Intrinsics.checkNotNullParameter((io.reactivex.rxjava3.disposables.b) it2, "it");
                this.b.j(Boolean.TRUE);
                break;
            default:
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.j(Boolean.FALSE);
                break;
        }
    }
}
