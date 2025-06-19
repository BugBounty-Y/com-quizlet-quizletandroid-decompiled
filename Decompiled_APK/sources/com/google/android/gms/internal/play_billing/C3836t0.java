package com.google.android.gms.internal.play_billing;

import com.google.android.gms.internal.ads.Wv;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

/* renamed from: com.google.android.gms.internal.play_billing.t0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3836t0 implements InterfaceFutureC3845w0 {
    public static final Wv a = new Wv(C3836t0.class, 1);

    @Override // com.google.android.gms.internal.play_billing.InterfaceFutureC3845w0
    public final void b(Runnable runnable, Executor executor) {
        if (executor == null) {
            throw new NullPointerException("Executor was null.");
        }
        try {
            executor.execute(runnable);
        } catch (Exception e) {
            a.a().logp(Level.SEVERE, "com.google.common.util.concurrent.ImmediateFuture", "addListener", android.support.v4.media.session.a.m("RuntimeException while executing runnable ", runnable.toString(), " with executor ", String.valueOf(executor)), (Throwable) e);
        }
    }

    @Override // java.util.concurrent.Future
    public final boolean cancel(boolean z) {
        return false;
    }

    @Override // java.util.concurrent.Future
    public final Object get() {
        return 0;
    }

    @Override // java.util.concurrent.Future
    public final boolean isCancelled() {
        return false;
    }

    @Override // java.util.concurrent.Future
    public final boolean isDone() {
        return true;
    }

    public final String toString() {
        Integer num = 0;
        return androidx.compose.ui.node.B.i(super.toString(), "[status=SUCCESS, result=[", num.toString(), "]]");
    }

    @Override // java.util.concurrent.Future
    public final Object get(long j, TimeUnit timeUnit) {
        timeUnit.getClass();
        return 0;
    }
}
