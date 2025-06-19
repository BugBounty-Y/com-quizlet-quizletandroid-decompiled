package io.reactivex.rxjava3.internal.schedulers;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;

/* loaded from: classes3.dex */
public final class q extends AtomicLong implements ThreadFactory {
    public final String a;
    public final int b;
    public final boolean c;

    public q(String str) {
        this(str, 5, false);
    }

    @Override // java.util.concurrent.ThreadFactory
    public final Thread newThread(Runnable runnable) {
        String str = this.a + '-' + incrementAndGet();
        Thread aVar = this.c ? new com.bumptech.glide.load.engine.executor.a(str, runnable) : new Thread(runnable, str);
        aVar.setPriority(this.b);
        aVar.setDaemon(true);
        return aVar;
    }

    @Override // java.util.concurrent.atomic.AtomicLong
    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("RxThreadFactory["), this.a, "]");
    }

    public q(String str, int i, boolean z) {
        this.a = str;
        this.b = i;
        this.c = z;
    }
}
