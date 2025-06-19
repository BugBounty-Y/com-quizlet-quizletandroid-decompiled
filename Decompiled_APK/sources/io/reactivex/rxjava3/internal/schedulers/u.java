package io.reactivex.rxjava3.internal.schedulers;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.Callable;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public final class u extends io.reactivex.rxjava3.core.n {
    public final ScheduledExecutorService a;
    public final io.reactivex.rxjava3.disposables.a b = new io.reactivex.rxjava3.disposables.a();
    public volatile boolean c;

    public u(ScheduledExecutorService scheduledExecutorService) {
        this.a = scheduledExecutorService;
    }

    @Override // io.reactivex.rxjava3.core.n
    public final io.reactivex.rxjava3.disposables.b b(Runnable runnable, long j, TimeUnit timeUnit) {
        boolean z = this.c;
        io.reactivex.rxjava3.internal.disposables.b bVar = io.reactivex.rxjava3.internal.disposables.b.a;
        if (z) {
            return bVar;
        }
        s sVar = new s(runnable, this.b, true);
        this.b.b(sVar);
        try {
            sVar.a(j <= 0 ? this.a.submit((Callable) sVar) : this.a.schedule((Callable) sVar, j, timeUnit));
            return sVar;
        } catch (RejectedExecutionException e) {
            dispose();
            C7.c(e);
            return bVar;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.c) {
            return;
        }
        this.c = true;
        this.b.dispose();
    }
}
