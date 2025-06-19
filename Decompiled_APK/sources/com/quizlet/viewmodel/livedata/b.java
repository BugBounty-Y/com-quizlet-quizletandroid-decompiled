package com.quizlet.viewmodel.livedata;

import androidx.lifecycle.J;
import androidx.lifecycle.T;
import com.quizlet.ads.ui.fragments.c;
import com.quizlet.quizletandroid.ui.subject.f;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends T {
    public final void m(J owner, Function0 onLoading, Function1 onRender) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(onLoading, "onLoading");
        Intrinsics.checkNotNullParameter(onRender, "onRender");
        f(owner, new c(new f(6, onLoading, onRender)));
    }

    public final void n() {
        j(com.quizlet.viewmodel.state.a.a);
    }

    public final void o(Object obj) {
        j(new com.quizlet.viewmodel.state.b(obj));
    }
}
