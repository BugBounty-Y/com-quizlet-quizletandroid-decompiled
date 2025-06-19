package io.reactivex.rxjava3.internal.schedulers;

import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public final class a extends io.reactivex.rxjava3.core.n {
    public final io.reactivex.rxjava3.internal.disposables.c a;
    public final io.reactivex.rxjava3.disposables.a b;
    public final io.reactivex.rxjava3.internal.disposables.c c;
    public final c d;
    public volatile boolean e;

    public a(c cVar) {
        this.d = cVar;
        io.reactivex.rxjava3.internal.disposables.c cVar2 = new io.reactivex.rxjava3.internal.disposables.c();
        this.a = cVar2;
        io.reactivex.rxjava3.disposables.a aVar = new io.reactivex.rxjava3.disposables.a();
        this.b = aVar;
        io.reactivex.rxjava3.internal.disposables.c cVar3 = new io.reactivex.rxjava3.internal.disposables.c();
        this.c = cVar3;
        cVar3.b(cVar2);
        cVar3.b(aVar);
    }

    @Override // io.reactivex.rxjava3.core.n
    public final io.reactivex.rxjava3.disposables.b a(Runnable runnable) {
        return this.e ? io.reactivex.rxjava3.internal.disposables.b.a : this.d.c(runnable, 0L, TimeUnit.MILLISECONDS, this.a);
    }

    @Override // io.reactivex.rxjava3.core.n
    public final io.reactivex.rxjava3.disposables.b b(Runnable runnable, long j, TimeUnit timeUnit) {
        return this.e ? io.reactivex.rxjava3.internal.disposables.b.a : this.d.c(runnable, j, timeUnit, this.b);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.e) {
            return;
        }
        this.e = true;
        this.c.dispose();
    }
}
