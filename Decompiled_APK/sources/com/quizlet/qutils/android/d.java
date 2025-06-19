package com.quizlet.qutils.android;

import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements InterfaceC1250k {
    public final /* synthetic */ Function0 a;

    public d(Function0 function0) {
        this.a = function0;
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onPause(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        this.a.invoke();
    }
}
