package com.quizlet.infra.legacysyncengine.datasources;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements io.reactivex.rxjava3.functions.d {
    public static final m a = new m();

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        Throwable it2 = (Throwable) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        timber.log.c.a(it2);
    }
}
