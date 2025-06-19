package com.google.android.gms.internal.ads;

import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.ld, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C2313ld implements com.google.common.util.concurrent.e {
    public final C1985dw a = new C1985dw();

    @Override // com.google.common.util.concurrent.e
    public final void a(Runnable runnable, Executor executor) {
        this.a.a(runnable, executor);
    }

    public final boolean c(Object obj) {
        boolean zG = this.a.g(obj);
        if (!zG) {
            com.google.android.gms.ads.internal.j.C.h.g("SettableFuture", new IllegalStateException("Provided SettableFuture with multiple values."));
        }
        return zG;
    }

    @Override // java.util.concurrent.Future
    public boolean cancel(boolean z) {
        return this.a.cancel(z);
    }

    public final boolean d(Throwable th) {
        boolean zH = this.a.h(th);
        if (!zH) {
            com.google.android.gms.ads.internal.j.C.h.g("SettableFuture", new IllegalStateException("Provided SettableFuture with multiple values."));
        }
        return zH;
    }

    @Override // java.util.concurrent.Future
    public final Object get() {
        return this.a.get();
    }

    @Override // java.util.concurrent.Future
    public final boolean isCancelled() {
        return this.a.a instanceof C2160hv;
    }

    @Override // java.util.concurrent.Future
    public final boolean isDone() {
        return this.a.isDone();
    }

    @Override // java.util.concurrent.Future
    public final Object get(long j, TimeUnit timeUnit) {
        return this.a.get(j, timeUnit);
    }
}
