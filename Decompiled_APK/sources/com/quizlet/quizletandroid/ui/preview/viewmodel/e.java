package com.quizlet.quizletandroid.ui.preview.viewmodel;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ g b;

    public /* synthetic */ e(g gVar, int i) {
        this.a = i;
        this.b = gVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.disposables.b it2 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.f.j(a.a);
                break;
            default:
                Throwable err = (Throwable) obj;
                Intrinsics.checkNotNullParameter(err, "err");
                timber.log.c.a.h(err);
                this.b.f.j(b.a);
                break;
        }
    }
}
