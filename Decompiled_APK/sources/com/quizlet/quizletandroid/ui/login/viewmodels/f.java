package com.quizlet.quizletandroid.ui.login.viewmodels;

import androidx.work.impl.model.v;
import io.reactivex.rxjava3.core.o;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Metadata;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class f extends com.quizlet.viewmodel.a {
    public final v d;
    public final com.quizlet.qutils.string.c e;
    public final o f;
    public final o g;
    public final s0 h;
    public final d0 i;
    public AtomicReference j;

    public f(v checkEmailUseCase, o networkScheduler, o mainThreadScheduler) {
        com.quizlet.qutils.string.c emailUtil = com.quizlet.qutils.string.c.a;
        Intrinsics.checkNotNullParameter(checkEmailUseCase, "checkEmailUseCase");
        Intrinsics.checkNotNullParameter(emailUtil, "emailUtil");
        Intrinsics.checkNotNullParameter(networkScheduler, "networkScheduler");
        Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
        this.d = checkEmailUseCase;
        this.e = emailUtil;
        this.f = networkScheduler;
        this.g = mainThreadScheduler;
        a aVar = a.a;
        this.h = e0.c(new h(aVar, aVar));
        this.i = e0.b(0, 0, null, 7);
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        Intrinsics.checkNotNullExpressionValue(dVar, "empty(...)");
        this.j = dVar;
    }

    public final void B(int i) {
        s0 s0Var;
        Object value;
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        com.quizlet.qutils.string.f fVar = new com.quizlet.qutils.string.f(i, C4933y.P(args));
        do {
            s0Var = this.h;
            value = s0Var.getValue();
        } while (!s0Var.k(value, h.a((h) value, new b(fVar), null, 2)));
    }
}
