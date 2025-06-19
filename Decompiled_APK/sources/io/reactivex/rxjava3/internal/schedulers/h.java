package io.reactivex.rxjava3.internal.schedulers;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes3.dex */
public final class h extends AtomicInteger implements Runnable, io.reactivex.rxjava3.disposables.b {
    public final Runnable a;
    public final io.reactivex.rxjava3.disposables.c b;
    public volatile Thread c;

    public h(Runnable runnable, io.reactivex.rxjava3.disposables.c cVar) {
        this.a = runnable;
        this.b = cVar;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        while (true) {
            int i = get();
            if (i >= 2) {
                return;
            }
            if (i == 0) {
                if (compareAndSet(0, 4)) {
                    io.reactivex.rxjava3.disposables.c cVar = this.b;
                    if (cVar != null) {
                        cVar.c(this);
                        return;
                    }
                    return;
                }
            } else if (compareAndSet(1, 3)) {
                Thread thread = this.c;
                if (thread != null) {
                    thread.interrupt();
                    this.c = null;
                }
                set(4);
                io.reactivex.rxjava3.disposables.c cVar2 = this.b;
                if (cVar2 != null) {
                    cVar2.c(this);
                    return;
                }
                return;
            }
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (get() == 0) {
            this.c = Thread.currentThread();
            if (!compareAndSet(0, 1)) {
                this.c = null;
                return;
            }
            try {
                this.a.run();
                this.c = null;
                if (!compareAndSet(1, 2)) {
                    while (get() == 3) {
                        Thread.yield();
                    }
                    Thread.interrupted();
                } else {
                    io.reactivex.rxjava3.disposables.c cVar = this.b;
                    if (cVar != null) {
                        cVar.c(this);
                    }
                }
            } catch (Throwable th) {
                try {
                    C7.c(th);
                    throw th;
                } catch (Throwable th2) {
                    this.c = null;
                    if (compareAndSet(1, 2)) {
                        io.reactivex.rxjava3.disposables.c cVar2 = this.b;
                        if (cVar2 != null) {
                            cVar2.c(this);
                        }
                    } else {
                        while (get() == 3) {
                            Thread.yield();
                        }
                        Thread.interrupted();
                    }
                    throw th2;
                }
            }
        }
    }
}
