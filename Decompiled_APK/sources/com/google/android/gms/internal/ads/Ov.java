package com.google.android.gms.internal.ads;

import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class Ov extends Nv {
    public final com.google.common.util.concurrent.e h;

    public Ov(com.google.common.util.concurrent.e eVar) {
        eVar.getClass();
        this.h = eVar;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov, com.google.common.util.concurrent.e
    public final void a(Runnable runnable, Executor executor) {
        this.h.a(runnable, executor);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov, java.util.concurrent.Future
    public final boolean cancel(boolean z) {
        return this.h.cancel(z);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov, java.util.concurrent.Future
    public final Object get() {
        return this.h.get();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov, java.util.concurrent.Future
    public final boolean isCancelled() {
        return this.h.isCancelled();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov, java.util.concurrent.Future
    public final boolean isDone() {
        return this.h.isDone();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final String toString() {
        return this.h.toString();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov, java.util.concurrent.Future
    public final Object get(long j, TimeUnit timeUnit) {
        return this.h.get(j, timeUnit);
    }
}
