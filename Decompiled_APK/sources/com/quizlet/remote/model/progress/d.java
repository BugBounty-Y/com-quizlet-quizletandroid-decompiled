package com.quizlet.remote.model.progress;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements io.reactivex.rxjava3.functions.d {
    public static final d a = new d();

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        Throwable error = (Throwable) obj;
        Intrinsics.checkNotNullParameter(error, "error");
        timber.log.c.a.i(error, "Network error trying to save ProgressReset", new Object[0]);
    }
}
