package io.reactivex.rxjava3.internal.schedulers;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class r extends AtomicReference implements Callable, io.reactivex.rxjava3.disposables.b {
    public static final FutureTask d;
    public static final FutureTask e;
    public final Runnable a;
    public final boolean b = true;
    public Thread c;

    static {
        androidx.emoji2.text.n nVar = io.reactivex.rxjava3.internal.functions.d.b;
        d = new FutureTask(nVar, null);
        e = new FutureTask(nVar, null);
    }

    public r(Runnable runnable) {
        this.a = runnable;
    }

    public final void a(Future future) {
        Future future2;
        do {
            future2 = (Future) get();
            if (future2 == d) {
                return;
            }
            if (future2 == e) {
                if (this.c == Thread.currentThread()) {
                    future.cancel(false);
                    return;
                } else {
                    future.cancel(this.b);
                    return;
                }
            }
        } while (!compareAndSet(future2, future));
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        FutureTask futureTask = d;
        this.c = Thread.currentThread();
        try {
            try {
                this.a.run();
                return null;
            } finally {
                lazySet(futureTask);
                this.c = null;
            }
        } catch (Throwable th) {
            C7.c(th);
            throw th;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        FutureTask futureTask;
        Future future = (Future) get();
        if (future == d || future == (futureTask = e) || !compareAndSet(future, futureTask) || future == null) {
            return;
        }
        if (this.c == Thread.currentThread()) {
            future.cancel(false);
        } else {
            future.cancel(this.b);
        }
    }

    @Override // java.util.concurrent.atomic.AtomicReference
    public final String toString() {
        String str;
        Future future = (Future) get();
        if (future == d) {
            str = "Finished";
        } else if (future == e) {
            str = "Disposed";
        } else if (this.c != null) {
            str = "Running on " + this.c;
        } else {
            str = "Waiting";
        }
        return r.class.getSimpleName() + "[" + str + "]";
    }
}
