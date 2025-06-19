package com.quizlet.offline.managers;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ long a;

    public h(long j) {
        this.a = j;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        Boolean isAvailable = (Boolean) obj;
        Intrinsics.checkNotNullParameter(isAvailable, "isAvailable");
        timber.log.c.a.g("Caching %s availability as %s", Long.valueOf(this.a), isAvailable);
    }
}
