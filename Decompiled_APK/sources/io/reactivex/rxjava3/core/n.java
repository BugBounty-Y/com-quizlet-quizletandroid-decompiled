package io.reactivex.rxjava3.core;

import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public abstract class n implements io.reactivex.rxjava3.disposables.b {
    public io.reactivex.rxjava3.disposables.b a(Runnable runnable) {
        return b(runnable, 0L, TimeUnit.NANOSECONDS);
    }

    public abstract io.reactivex.rxjava3.disposables.b b(Runnable runnable, long j, TimeUnit timeUnit);
}
