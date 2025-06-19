package com.google.android.gms.measurement.internal;

import java.util.concurrent.Callable;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class X extends AbstractC3871h0 {
    public static final AtomicLong l = new AtomicLong(Long.MIN_VALUE);
    public W d;
    public W e;
    public final PriorityBlockingQueue f;
    public final LinkedBlockingQueue g;
    public final U h;
    public final U i;
    public final Object j;
    public final Semaphore k;

    public X(Y y) {
        super(y);
        this.j = new Object();
        this.k = new Semaphore(2);
        this.f = new PriorityBlockingQueue();
        this.g = new LinkedBlockingQueue();
        this.h = new U(this, "Thread death: Uncaught exception on worker thread");
        this.i = new U(this, "Thread death: Uncaught exception on network thread");
    }

    @Override // androidx.compose.animation.core.J0
    public final void S() {
        if (Thread.currentThread() != this.d) {
            throw new IllegalStateException("Call expected from worker thread");
        }
    }

    @Override // com.google.android.gms.measurement.internal.AbstractC3871h0
    public final boolean T() {
        return false;
    }

    public final void W() {
        if (Thread.currentThread() != this.e) {
            throw new IllegalStateException("Call expected from network thread");
        }
    }

    public final Object X(AtomicReference atomicReference, long j, String str, Runnable runnable) {
        synchronized (atomicReference) {
            X x = ((Y) this.b).j;
            Y.k(x);
            x.c0(runnable);
            try {
                atomicReference.wait(j);
            } catch (InterruptedException unused) {
                I i = ((Y) this.b).i;
                Y.k(i);
                i.j.f("Interrupted waiting for ".concat(str));
                return null;
            }
        }
        Object obj = atomicReference.get();
        if (obj == null) {
            I i2 = ((Y) this.b).i;
            Y.k(i2);
            i2.j.f("Timed out waiting for ".concat(str));
        }
        return obj;
    }

    public final V Y(Callable callable) {
        U();
        V v = new V(this, callable, false);
        if (Thread.currentThread() != this.d) {
            f0(v);
            return v;
        }
        if (!this.f.isEmpty()) {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.j.f("Callable skipped the worker queue.");
        }
        v.run();
        return v;
    }

    public final V Z(Callable callable) {
        U();
        V v = new V(this, callable, true);
        if (Thread.currentThread() == this.d) {
            v.run();
            return v;
        }
        f0(v);
        return v;
    }

    public final void a0() {
        if (Thread.currentThread() == this.d) {
            throw new IllegalStateException("Call not expected from worker thread");
        }
    }

    public final void b0(Runnable runnable) {
        U();
        V v = new V(this, runnable, false, "Task exception on network thread");
        synchronized (this.j) {
            try {
                LinkedBlockingQueue linkedBlockingQueue = this.g;
                linkedBlockingQueue.add(v);
                W w = this.e;
                if (w == null) {
                    W w2 = new W(this, "Measurement Network", linkedBlockingQueue);
                    this.e = w2;
                    w2.setUncaughtExceptionHandler(this.i);
                    this.e.start();
                } else {
                    Object obj = w.a;
                    synchronized (obj) {
                        obj.notifyAll();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void c0(Runnable runnable) {
        U();
        com.google.android.gms.common.internal.u.h(runnable);
        f0(new V(this, runnable, false, "Task exception on worker thread"));
    }

    public final void d0(Runnable runnable) {
        U();
        f0(new V(this, runnable, true, "Task exception on worker thread"));
    }

    public final boolean e0() {
        return Thread.currentThread() == this.d;
    }

    public final void f0(V v) {
        synchronized (this.j) {
            try {
                PriorityBlockingQueue priorityBlockingQueue = this.f;
                priorityBlockingQueue.add(v);
                W w = this.d;
                if (w == null) {
                    W w2 = new W(this, "Measurement Worker", priorityBlockingQueue);
                    this.d = w2;
                    w2.setUncaughtExceptionHandler(this.h);
                    this.d.start();
                } else {
                    Object obj = w.a;
                    synchronized (obj) {
                        obj.notifyAll();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
