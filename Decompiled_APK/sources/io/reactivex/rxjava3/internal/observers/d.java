package io.reactivex.rxjava3.internal.observers;

import io.reactivex.rxjava3.core.q;
import java.util.concurrent.CountDownLatch;

/* loaded from: classes3.dex */
public final class d extends CountDownLatch implements q, io.reactivex.rxjava3.core.b, io.reactivex.rxjava3.core.h {
    public Object a;
    public Throwable b;
    public io.reactivex.rxjava3.disposables.b c;
    public volatile boolean d;

    @Override // io.reactivex.rxjava3.core.q
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        this.c = bVar;
        if (this.d) {
            bVar.dispose();
        }
    }

    public final Object b() throws InterruptedException {
        if (getCount() != 0) {
            try {
                await();
            } catch (InterruptedException e) {
                this.d = true;
                io.reactivex.rxjava3.disposables.b bVar = this.c;
                if (bVar != null) {
                    bVar.dispose();
                }
                throw io.reactivex.rxjava3.internal.util.c.d(e);
            }
        }
        Throwable th = this.b;
        if (th == null) {
            return this.a;
        }
        throw io.reactivex.rxjava3.internal.util.c.d(th);
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onComplete() {
        countDown();
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void onError(Throwable th) {
        this.b = th;
        countDown();
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        this.a = obj;
        countDown();
    }
}
