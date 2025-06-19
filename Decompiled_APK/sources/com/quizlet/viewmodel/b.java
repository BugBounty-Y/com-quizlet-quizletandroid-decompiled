package com.quizlet.viewmodel;

import androidx.lifecycle.w0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b extends w0 {
    public io.reactivex.rxjava3.disposables.a b;

    public final void A(io.reactivex.rxjava3.disposables.b subscription) {
        Intrinsics.checkNotNullParameter(subscription, "subscription");
        if (this.b == null) {
            this.b = new io.reactivex.rxjava3.disposables.a();
        }
        io.reactivex.rxjava3.disposables.a aVar = this.b;
        if (aVar != null) {
            aVar.b(subscription);
        }
    }

    @Override // androidx.lifecycle.w0
    public void z() {
        io.reactivex.rxjava3.disposables.a aVar = this.b;
        if (aVar != null) {
            aVar.d();
        }
    }
}
