package com.google.android.gms.internal.play_billing;

import java.util.Locale;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import java.util.concurrent.locks.LockSupport;
import java.util.logging.Level;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public class l2 implements InterfaceFutureC3845w0 {
    public static final boolean d = Boolean.parseBoolean(System.getProperty("guava.concurrent.generate_cancellation_cause", "false"));
    public static final Logger e = Logger.getLogger(l2.class.getName());
    public static final Z0 f;
    public static final Object g;
    public volatile Object a;
    public volatile A1 b;
    public volatile k2 c;

    static {
        Z0 j2Var;
        try {
            j2Var = new X1(AtomicReferenceFieldUpdater.newUpdater(k2.class, Thread.class, "a"), AtomicReferenceFieldUpdater.newUpdater(k2.class, k2.class, "b"), AtomicReferenceFieldUpdater.newUpdater(l2.class, k2.class, "c"), AtomicReferenceFieldUpdater.newUpdater(l2.class, A1.class, "b"), AtomicReferenceFieldUpdater.newUpdater(l2.class, Object.class, "a"));
            th = null;
        } catch (Throwable th) {
            th = th;
            j2Var = new j2(9);
        }
        Throwable th2 = th;
        f = j2Var;
        if (th2 != null) {
            e.logp(Level.SEVERE, "com.android.billingclient.util.concurrent.AbstractResolvableFuture", "<clinit>", "SafeAtomicHelper is broken!", th2);
        }
        g = new Object();
    }

    public static void d(l2 l2Var) {
        k2 k2Var;
        A1 a1;
        A1 a12;
        A1 a13;
        do {
            k2Var = l2Var.c;
        } while (!f.B(l2Var, k2Var, k2.c));
        while (true) {
            a1 = null;
            if (k2Var == null) {
                break;
            }
            Thread thread = k2Var.a;
            if (thread != null) {
                k2Var.a = null;
                LockSupport.unpark(thread);
            }
            k2Var = k2Var.b;
        }
        do {
            a12 = l2Var.b;
        } while (!f.u(l2Var, a12, A1.d));
        while (true) {
            a13 = a1;
            a1 = a12;
            if (a1 == null) {
                break;
            }
            a12 = a1.c;
            a1.c = a13;
        }
        while (a13 != null) {
            Runnable runnable = a13.a;
            A1 a14 = a13.c;
            f(runnable, a13.b);
            a13 = a14;
        }
    }

    public static void f(Runnable runnable, Executor executor) {
        try {
            executor.execute(runnable);
        } catch (RuntimeException e2) {
            e.logp(Level.SEVERE, "com.android.billingclient.util.concurrent.AbstractResolvableFuture", "executeListener", android.support.v4.media.session.a.m("RuntimeException while executing runnable ", String.valueOf(runnable), " with executor ", String.valueOf(executor)), (Throwable) e2);
        }
    }

    public static final Object h(Object obj) throws ExecutionException {
        if (obj instanceof S0) {
            CancellationException cancellationException = ((S0) obj).a;
            CancellationException cancellationException2 = new CancellationException("Task was cancelled.");
            cancellationException2.initCause(cancellationException);
            throw cancellationException2;
        }
        if (obj instanceof C3811k1) {
            throw new ExecutionException(((C3811k1) obj).a);
        }
        if (obj == g) {
            return null;
        }
        return obj;
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceFutureC3845w0
    public final void b(Runnable runnable, Executor executor) {
        executor.getClass();
        A1 a1 = this.b;
        A1 a12 = A1.d;
        if (a1 != a12) {
            A1 a13 = new A1(runnable, executor);
            do {
                a13.c = a1;
                if (f.u(this, a1, a13)) {
                    return;
                } else {
                    a1 = this.b;
                }
            } while (a1 != a12);
        }
        f(runnable, executor);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public String c() {
        if (this instanceof ScheduledFuture) {
            return androidx.compose.animation.d0.o(((ScheduledFuture) this).getDelay(TimeUnit.MILLISECONDS), "remaining delay=[", " ms]");
        }
        return null;
    }

    @Override // java.util.concurrent.Future
    public final boolean cancel(boolean z) {
        Object obj = this.a;
        if (obj != null) {
            return false;
        }
        if (!f.w(this, obj, d ? new S0(new CancellationException("Future.cancel() was called.")) : z ? S0.b : S0.c)) {
            return false;
        }
        d(this);
        return true;
    }

    public final void e(StringBuilder sb) {
        Object obj;
        boolean z = false;
        while (true) {
            try {
                try {
                    obj = get();
                    break;
                } catch (InterruptedException unused) {
                    z = true;
                } catch (Throwable th) {
                    if (z) {
                        Thread.currentThread().interrupt();
                    }
                    throw th;
                }
            } catch (CancellationException unused2) {
                sb.append("CANCELLED");
                return;
            } catch (RuntimeException e2) {
                sb.append("UNKNOWN, cause=[");
                sb.append(e2.getClass());
                sb.append(" thrown from get()]");
                return;
            } catch (ExecutionException e3) {
                sb.append("FAILURE, cause=[");
                sb.append(e3.getCause());
                sb.append("]");
                return;
            }
        }
        if (z) {
            Thread.currentThread().interrupt();
        }
        sb.append("SUCCESS, result=[");
        sb.append(obj == this ? "this future" : String.valueOf(obj));
        sb.append("]");
    }

    public final void g(k2 k2Var) {
        k2Var.a = null;
        while (true) {
            k2 k2Var2 = this.c;
            if (k2Var2 != k2.c) {
                k2 k2Var3 = null;
                while (k2Var2 != null) {
                    k2 k2Var4 = k2Var2.b;
                    if (k2Var2.a != null) {
                        k2Var3 = k2Var2;
                    } else if (k2Var3 != null) {
                        k2Var3.b = k2Var4;
                        if (k2Var3.a == null) {
                            break;
                        }
                    } else if (!f.B(this, k2Var2, k2Var4)) {
                        break;
                    }
                    k2Var2 = k2Var4;
                }
                return;
            }
            return;
        }
    }

    @Override // java.util.concurrent.Future
    public final Object get() throws InterruptedException {
        Object obj;
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }
        Object obj2 = this.a;
        if (obj2 != null) {
            return h(obj2);
        }
        k2 k2Var = this.c;
        k2 k2Var2 = k2.c;
        if (k2Var != k2Var2) {
            k2 k2Var3 = new k2();
            do {
                Z0 z0 = f;
                z0.j(k2Var3, k2Var);
                if (z0.B(this, k2Var, k2Var3)) {
                    do {
                        LockSupport.park(this);
                        if (Thread.interrupted()) {
                            g(k2Var3);
                            throw new InterruptedException();
                        }
                        obj = this.a;
                    } while (obj == null);
                    return h(obj);
                }
                k2Var = this.c;
            } while (k2Var != k2Var2);
        }
        return h(this.a);
    }

    @Override // java.util.concurrent.Future
    public final boolean isCancelled() {
        return this.a instanceof S0;
    }

    @Override // java.util.concurrent.Future
    public final boolean isDone() {
        return this.a != null;
    }

    public final String toString() {
        String strConcat;
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());
        sb.append("[status=");
        if (this.a instanceof S0) {
            sb.append("CANCELLED");
        } else if (isDone()) {
            e(sb);
        } else {
            try {
                strConcat = c();
            } catch (RuntimeException e2) {
                strConcat = "Exception thrown from implementation: ".concat(String.valueOf(e2.getClass()));
            }
            if (strConcat != null && !strConcat.isEmpty()) {
                sb.append("PENDING, info=[");
                sb.append(strConcat);
                sb.append("]");
            } else if (isDone()) {
                e(sb);
            } else {
                sb.append("PENDING");
            }
        }
        sb.append("]");
        return sb.toString();
    }

    @Override // java.util.concurrent.Future
    public final Object get(long j, TimeUnit timeUnit) throws InterruptedException, TimeoutException {
        long nanos = timeUnit.toNanos(j);
        if (!Thread.interrupted()) {
            Object obj = this.a;
            if (obj != null) {
                return h(obj);
            }
            long jNanoTime = nanos > 0 ? System.nanoTime() + nanos : 0L;
            if (nanos >= 1000) {
                k2 k2Var = this.c;
                k2 k2Var2 = k2.c;
                if (k2Var != k2Var2) {
                    k2 k2Var3 = new k2();
                    do {
                        Z0 z0 = f;
                        z0.j(k2Var3, k2Var);
                        if (z0.B(this, k2Var, k2Var3)) {
                            do {
                                LockSupport.parkNanos(this, nanos);
                                if (!Thread.interrupted()) {
                                    Object obj2 = this.a;
                                    if (obj2 != null) {
                                        return h(obj2);
                                    }
                                    nanos = jNanoTime - System.nanoTime();
                                } else {
                                    g(k2Var3);
                                    throw new InterruptedException();
                                }
                            } while (nanos >= 1000);
                            g(k2Var3);
                        } else {
                            k2Var = this.c;
                        }
                    } while (k2Var != k2Var2);
                }
                return h(this.a);
            }
            while (nanos > 0) {
                Object obj3 = this.a;
                if (obj3 != null) {
                    return h(obj3);
                }
                if (!Thread.interrupted()) {
                    nanos = jNanoTime - System.nanoTime();
                } else {
                    throw new InterruptedException();
                }
            }
            String string = toString();
            String string2 = timeUnit.toString();
            Locale locale = Locale.ROOT;
            String lowerCase = string2.toLowerCase(locale);
            String strConcat = "Waited " + j + " " + timeUnit.toString().toLowerCase(locale);
            if (nanos + 1000 < 0) {
                String strConcat2 = strConcat.concat(" (plus ");
                long j2 = -nanos;
                long jConvert = timeUnit.convert(j2, TimeUnit.NANOSECONDS);
                long nanos2 = j2 - timeUnit.toNanos(jConvert);
                boolean z = true;
                if (jConvert != 0 && nanos2 <= 1000) {
                    z = false;
                }
                if (jConvert > 0) {
                    String strConcat3 = strConcat2 + jConvert + " " + lowerCase;
                    if (z) {
                        strConcat3 = strConcat3.concat(",");
                    }
                    strConcat2 = strConcat3.concat(" ");
                }
                if (z) {
                    strConcat2 = strConcat2 + nanos2 + " nanoseconds ";
                }
                strConcat = strConcat2.concat("delay)");
            }
            if (isDone()) {
                throw new TimeoutException(strConcat.concat(" but future completed as timeout expired"));
            }
            throw new TimeoutException(android.support.v4.media.session.a.l(strConcat, " for ", string));
        }
        throw new InterruptedException();
    }
}
