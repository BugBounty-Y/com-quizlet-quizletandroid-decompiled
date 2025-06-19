package io.reactivex.rxjava3.internal.schedulers;

import androidx.compose.ui.node.B;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReferenceArray;

/* loaded from: classes3.dex */
public final class s extends AtomicReferenceArray implements Runnable, Callable, io.reactivex.rxjava3.disposables.b {
    public static final Object c = new Object();
    public static final Object d = new Object();
    public static final Object e = new Object();
    public static final Object f = new Object();
    public final Runnable a;
    public final boolean b;

    public s(Runnable runnable, io.reactivex.rxjava3.disposables.c cVar, boolean z) {
        super(3);
        this.a = runnable;
        this.b = z;
        lazySet(0, cVar);
    }

    public final void a(Future future) {
        Object obj;
        do {
            obj = get(1);
            if (obj == f) {
                return;
            }
            if (obj == d) {
                future.cancel(false);
                return;
            } else if (obj == e) {
                future.cancel(this.b);
                return;
            }
        } while (!compareAndSet(1, obj, future));
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        run();
        return null;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        Object obj;
        Object obj2;
        Object obj3;
        Object obj4;
        Object obj5;
        while (true) {
            Object obj6 = get(1);
            obj = f;
            if (obj6 == obj || obj6 == (obj4 = d) || obj6 == (obj5 = e)) {
                break;
            }
            boolean z = get(2) != Thread.currentThread();
            if (z) {
                obj4 = obj5;
            }
            if (compareAndSet(1, obj6, obj4)) {
                if (obj6 != null) {
                    ((Future) obj6).cancel(z && this.b);
                }
            }
        }
        do {
            obj2 = get(0);
            if (obj2 == obj || obj2 == (obj3 = c) || obj2 == null) {
                return;
            }
        } while (!compareAndSet(0, obj2, obj3));
        ((io.reactivex.rxjava3.disposables.c) obj2).c(this);
    }

    @Override // java.lang.Runnable
    public final void run() {
        Object obj;
        Object obj2;
        Object obj3 = e;
        Object obj4 = d;
        Object obj5 = c;
        Object obj6 = f;
        lazySet(2, Thread.currentThread());
        try {
            this.a.run();
            Object obj7 = get(0);
            if (obj7 != obj5 && compareAndSet(0, obj7, obj6) && obj7 != null) {
                ((io.reactivex.rxjava3.disposables.c) obj7).c(this);
            }
            do {
                obj2 = get(1);
                if (obj2 == obj4 || obj2 == obj3) {
                    break;
                }
            } while (!compareAndSet(1, obj2, obj6));
            lazySet(2, null);
        } catch (Throwable th) {
            try {
                C7.c(th);
                throw th;
            } catch (Throwable th2) {
                Object obj8 = get(0);
                if (obj8 != obj5 && compareAndSet(0, obj8, obj6) && obj8 != null) {
                    ((io.reactivex.rxjava3.disposables.c) obj8).c(this);
                }
                do {
                    obj = get(1);
                    if (obj == obj4 || obj == obj3) {
                        break;
                    }
                } while (!compareAndSet(1, obj, obj6));
                lazySet(2, null);
                throw th2;
            }
        }
    }

    @Override // java.util.concurrent.atomic.AtomicReferenceArray
    public final String toString() {
        String strE;
        Object obj = get(1);
        if (obj == f) {
            strE = "Finished";
        } else if (obj == d) {
            strE = "Disposed(Sync)";
        } else if (obj == e) {
            strE = "Disposed(Async)";
        } else {
            Object obj2 = get(2);
            strE = obj2 == null ? "Waiting" : B.e(obj2, "Running on ");
        }
        return s.class.getSimpleName() + "[" + strE + "]";
    }
}
