package com.quizlet.billing.manager;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c implements io.reactivex.rxjava3.functions.d {
    public static final c a = new c();

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        Throwable it2 = (Throwable) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        timber.log.c.a.d(it2.getMessage(), new Object[0]);
    }
}
