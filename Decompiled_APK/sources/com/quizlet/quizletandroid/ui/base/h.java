package com.quizlet.quizletandroid.ui.base;

import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import com.quizlet.quizletandroid.t;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes3.dex */
public final class h implements InterfaceC1250k {
    public final com.quizlet.baseui.managers.b a;
    public final t b;
    public final com.quizlet.data.repository.user.a c;
    public final u d;

    public h(com.quizlet.baseui.managers.b componentLifecycleDisposableManager, t compositeDisposableProvider, com.quizlet.data.repository.user.a gaLogger) {
        Intrinsics.checkNotNullParameter(componentLifecycleDisposableManager, "componentLifecycleDisposableManager");
        Intrinsics.checkNotNullParameter(compositeDisposableProvider, "compositeDisposableProvider");
        Intrinsics.checkNotNullParameter(gaLogger, "gaLogger");
        this.a = componentLifecycleDisposableManager;
        this.b = compositeDisposableProvider;
        this.c = gaLogger;
        this.d = l.b(new com.quizlet.login.magiclink.ui.e(this, 8));
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onDestroy(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        Object value = this.d.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).d();
    }
}
