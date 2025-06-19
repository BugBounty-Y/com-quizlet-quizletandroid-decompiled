package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class i0 extends AtomicReference implements Runnable, io.reactivex.rxjava3.functions.d {
    public final C4896o a;
    public long b;
    public boolean c;
    public boolean d;

    public i0(C4896o c4896o) {
        this.a = c4896o;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        io.reactivex.rxjava3.internal.disposables.a.c(this, (io.reactivex.rxjava3.disposables.b) obj);
        synchronized (this.a) {
            try {
                if (this.d) {
                    ((io.reactivex.rxjava3.internal.operators.mixed.b) this.a.b).z();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.a.A(this);
    }
}
