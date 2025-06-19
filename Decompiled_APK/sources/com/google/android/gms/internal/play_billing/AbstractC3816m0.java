package com.google.android.gms.internal.play_billing;

import com.google.android.gms.internal.ads.Wv;
import java.util.Locale;
import java.util.Objects;
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

/* renamed from: com.google.android.gms.internal.play_billing.m0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3816m0 extends H0 implements InterfaceFutureC3845w0 {
    public static final boolean d;
    public static final Wv e;
    public static final Z0 f;
    public static final Object g;
    public volatile Object a;
    public volatile C3792e0 b;
    public volatile C3813l0 c;

    static {
        boolean z;
        Z0 c3801h0;
        Throwable th;
        int i = 7;
        try {
            z = Boolean.parseBoolean(System.getProperty("guava.concurrent.generate_cancellation_cause", "false"));
        } catch (SecurityException unused) {
            z = false;
        }
        d = z;
        e = new Wv(AbstractC3816m0.class, 1);
        Throwable th2 = null;
        try {
            c3801h0 = new C3810k0(i);
            th = null;
        } catch (Error | Exception e2) {
            try {
                th = e2;
                c3801h0 = new C3795f0(AtomicReferenceFieldUpdater.newUpdater(C3813l0.class, Thread.class, "a"), AtomicReferenceFieldUpdater.newUpdater(C3813l0.class, C3813l0.class, "b"), AtomicReferenceFieldUpdater.newUpdater(AbstractC3816m0.class, C3813l0.class, "c"), AtomicReferenceFieldUpdater.newUpdater(AbstractC3816m0.class, C3792e0.class, "b"), AtomicReferenceFieldUpdater.newUpdater(AbstractC3816m0.class, Object.class, "a"));
            } catch (Error | Exception e3) {
                th2 = e3;
                c3801h0 = new C3801h0(i);
                th = e2;
            }
        }
        f = c3801h0;
        if (th2 != null) {
            Wv wv = e;
            Logger loggerA = wv.a();
            Level level = Level.SEVERE;
            loggerA.logp(level, "com.google.common.util.concurrent.AbstractFuture", "<clinit>", "UnsafeAtomicHelper is broken!", th);
            wv.a().logp(level, "com.google.common.util.concurrent.AbstractFuture", "<clinit>", "SafeAtomicHelper is broken!", th2);
        }
        g = new Object();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0042  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Object f(com.google.android.gms.internal.play_billing.InterfaceFutureC3845w0 r6) {
        /*
            java.lang.String r0 = "get() did not throw CancellationException, despite reporting isCancelled() == true: "
            boolean r1 = r6 instanceof com.google.android.gms.internal.play_billing.InterfaceC3804i0
            r2 = 0
            if (r1 == 0) goto L27
            com.google.android.gms.internal.play_billing.m0 r6 = (com.google.android.gms.internal.play_billing.AbstractC3816m0) r6
            java.lang.Object r6 = r6.a
            boolean r0 = r6 instanceof com.google.android.gms.internal.play_billing.C3786c0
            if (r0 == 0) goto L23
            r0 = r6
            com.google.android.gms.internal.play_billing.c0 r0 = (com.google.android.gms.internal.play_billing.C3786c0) r0
            boolean r1 = r0.a
            if (r1 == 0) goto L23
            java.lang.RuntimeException r6 = r0.b
            if (r6 == 0) goto L21
            com.google.android.gms.internal.play_billing.c0 r0 = new com.google.android.gms.internal.play_billing.c0
            r0.<init>(r2, r6)
            r6 = r0
            goto L23
        L21:
            com.google.android.gms.internal.play_billing.c0 r6 = com.google.android.gms.internal.play_billing.C3786c0.d
        L23:
            java.util.Objects.requireNonNull(r6)
            return r6
        L27:
            boolean r1 = r6 instanceof com.google.android.gms.internal.play_billing.H0
            if (r1 == 0) goto L4c
            r1 = r6
            com.google.android.gms.internal.play_billing.H0 r1 = (com.google.android.gms.internal.play_billing.H0) r1
            com.google.android.gms.internal.play_billing.m0 r1 = (com.google.android.gms.internal.play_billing.AbstractC3816m0) r1
            r1.getClass()
            boolean r3 = r1 instanceof com.google.android.gms.internal.play_billing.InterfaceC3804i0
            if (r3 == 0) goto L42
            java.lang.Object r1 = r1.a
            boolean r3 = r1 instanceof com.google.android.gms.internal.play_billing.C3789d0
            if (r3 == 0) goto L42
            com.google.android.gms.internal.play_billing.d0 r1 = (com.google.android.gms.internal.play_billing.C3789d0) r1
            java.lang.Throwable r1 = r1.a
            goto L43
        L42:
            r1 = 0
        L43:
            if (r1 != 0) goto L46
            goto L4c
        L46:
            com.google.android.gms.internal.play_billing.d0 r6 = new com.google.android.gms.internal.play_billing.d0
            r6.<init>(r1)
            return r6
        L4c:
            boolean r1 = r6.isCancelled()
            boolean r3 = com.google.android.gms.internal.play_billing.AbstractC3816m0.d
            r3 = r3 ^ 1
            r3 = r3 & r1
            if (r3 == 0) goto L5d
            com.google.android.gms.internal.play_billing.c0 r6 = com.google.android.gms.internal.play_billing.C3786c0.d
            java.util.Objects.requireNonNull(r6)
            return r6
        L5d:
            java.lang.Object r3 = g(r6)     // Catch: java.lang.Error -> L76 java.util.concurrent.CancellationException -> L78 java.util.concurrent.ExecutionException -> L7a java.lang.Throwable -> L81
            if (r1 == 0) goto L7c
            com.google.android.gms.internal.play_billing.c0 r3 = new com.google.android.gms.internal.play_billing.c0     // Catch: java.util.concurrent.CancellationException -> L78 java.util.concurrent.ExecutionException -> L7a java.lang.Throwable -> L81
            java.lang.IllegalArgumentException r4 = new java.lang.IllegalArgumentException     // Catch: java.util.concurrent.CancellationException -> L78 java.util.concurrent.ExecutionException -> L7a java.lang.Throwable -> L81
            java.lang.String r5 = java.lang.String.valueOf(r6)     // Catch: java.util.concurrent.CancellationException -> L78 java.util.concurrent.ExecutionException -> L7a java.lang.Throwable -> L81
            java.lang.String r5 = r0.concat(r5)     // Catch: java.util.concurrent.CancellationException -> L78 java.util.concurrent.ExecutionException -> L7a java.lang.Throwable -> L81
            r4.<init>(r5)     // Catch: java.util.concurrent.CancellationException -> L78 java.util.concurrent.ExecutionException -> L7a java.lang.Throwable -> L81
            r3.<init>(r2, r4)     // Catch: java.lang.Error -> L76 java.util.concurrent.CancellationException -> L78 java.util.concurrent.ExecutionException -> L7a java.lang.Throwable -> L81
            return r3
        L76:
            r6 = move-exception
            goto L84
        L78:
            r0 = move-exception
            goto L8a
        L7a:
            r3 = move-exception
            goto La7
        L7c:
            if (r3 != 0) goto L83
            java.lang.Object r6 = com.google.android.gms.internal.play_billing.AbstractC3816m0.g     // Catch: java.util.concurrent.CancellationException -> L78 java.util.concurrent.ExecutionException -> L7a java.lang.Throwable -> L81 java.lang.Throwable -> L81
            return r6
        L81:
            r6 = move-exception
            goto L84
        L83:
            return r3
        L84:
            com.google.android.gms.internal.play_billing.d0 r0 = new com.google.android.gms.internal.play_billing.d0
            r0.<init>(r6)
            return r0
        L8a:
            if (r1 != 0) goto La1
            com.google.android.gms.internal.play_billing.d0 r1 = new com.google.android.gms.internal.play_billing.d0
            java.lang.IllegalArgumentException r2 = new java.lang.IllegalArgumentException
            java.lang.String r6 = java.lang.String.valueOf(r6)
            java.lang.String r3 = "get() threw CancellationException, despite reporting isCancelled() == false: "
            java.lang.String r6 = r3.concat(r6)
            r2.<init>(r6, r0)
            r1.<init>(r2)
            return r1
        La1:
            com.google.android.gms.internal.play_billing.c0 r6 = new com.google.android.gms.internal.play_billing.c0
            r6.<init>(r2, r0)
            return r6
        La7:
            if (r1 == 0) goto Lbc
            com.google.android.gms.internal.play_billing.c0 r1 = new com.google.android.gms.internal.play_billing.c0
            java.lang.IllegalArgumentException r4 = new java.lang.IllegalArgumentException
            java.lang.String r6 = java.lang.String.valueOf(r6)
            java.lang.String r6 = r0.concat(r6)
            r4.<init>(r6, r3)
            r1.<init>(r2, r4)
            return r1
        Lbc:
            com.google.android.gms.internal.play_billing.d0 r6 = new com.google.android.gms.internal.play_billing.d0
            java.lang.Throwable r0 = r3.getCause()
            r6.<init>(r0)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.AbstractC3816m0.f(com.google.android.gms.internal.play_billing.w0):java.lang.Object");
    }

    public static Object g(InterfaceFutureC3845w0 interfaceFutureC3845w0) {
        Object obj;
        boolean z = false;
        while (true) {
            try {
                obj = interfaceFutureC3845w0.get();
                break;
            } catch (InterruptedException unused) {
                z = true;
            } catch (Throwable th) {
                if (z) {
                    Thread.currentThread().interrupt();
                }
                throw th;
            }
        }
        if (z) {
            Thread.currentThread().interrupt();
        }
        return obj;
    }

    public static void i(AbstractC3816m0 abstractC3816m0) {
        C3792e0 c3792e0;
        C3792e0 c3792e02 = null;
        while (true) {
            for (C3813l0 c3813l0P = f.p(abstractC3816m0); c3813l0P != null; c3813l0P = c3813l0P.b) {
                Thread thread = c3813l0P.a;
                if (thread != null) {
                    c3813l0P.a = null;
                    LockSupport.unpark(thread);
                }
            }
            abstractC3816m0.d();
            C3792e0 c3792e03 = c3792e02;
            C3792e0 c3792e0E = f.e(abstractC3816m0);
            C3792e0 c3792e04 = c3792e03;
            while (c3792e0E != null) {
                C3792e0 c3792e05 = c3792e0E.c;
                c3792e0E.c = c3792e04;
                c3792e04 = c3792e0E;
                c3792e0E = c3792e05;
            }
            while (c3792e04 != null) {
                Runnable runnable = c3792e04.a;
                c3792e0 = c3792e04.c;
                Objects.requireNonNull(runnable);
                if (runnable instanceof RunnableC3798g0) {
                    RunnableC3798g0 runnableC3798g0 = (RunnableC3798g0) runnable;
                    abstractC3816m0 = runnableC3798g0.a;
                    if (abstractC3816m0.a == runnableC3798g0) {
                        if (f.E(abstractC3816m0, runnableC3798g0, f(runnableC3798g0.b))) {
                            break;
                        }
                    } else {
                        continue;
                    }
                } else {
                    Executor executor = c3792e04.b;
                    Objects.requireNonNull(executor);
                    j(runnable, executor);
                }
                c3792e04 = c3792e0;
            }
            return;
            c3792e02 = c3792e0;
        }
    }

    public static void j(Runnable runnable, Executor executor) {
        try {
            executor.execute(runnable);
        } catch (Exception e2) {
            e.a().logp(Level.SEVERE, "com.google.common.util.concurrent.AbstractFuture", "executeListener", android.support.v4.media.session.a.m("RuntimeException while executing runnable ", String.valueOf(runnable), " with executor ", String.valueOf(executor)), (Throwable) e2);
        }
    }

    public static final Object l(Object obj) throws ExecutionException {
        if (obj instanceof C3786c0) {
            RuntimeException runtimeException = ((C3786c0) obj).b;
            CancellationException cancellationException = new CancellationException("Task was cancelled.");
            cancellationException.initCause(runtimeException);
            throw cancellationException;
        }
        if (obj instanceof C3789d0) {
            throw new ExecutionException(((C3789d0) obj).a);
        }
        if (obj == g) {
            return null;
        }
        return obj;
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceFutureC3845w0
    public final void b(Runnable runnable, Executor executor) {
        C3792e0 c3792e0;
        C3792e0 c3792e02;
        if (executor == null) {
            throw new NullPointerException("Executor was null.");
        }
        if (!isDone() && (c3792e0 = this.b) != (c3792e02 = C3792e0.d)) {
            C3792e0 c3792e03 = new C3792e0(runnable, executor);
            do {
                c3792e03.c = c3792e0;
                if (f.A(this, c3792e0, c3792e03)) {
                    return;
                } else {
                    c3792e0 = this.b;
                }
            } while (c3792e0 != c3792e02);
        }
        j(runnable, executor);
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
        C3786c0 c3786c0;
        Object obj = this.a;
        if (!(obj instanceof RunnableC3798g0) && !(obj == null)) {
            return false;
        }
        if (d) {
            c3786c0 = new C3786c0(z, new CancellationException("Future.cancel() was called."));
        } else {
            c3786c0 = z ? C3786c0.c : C3786c0.d;
            Objects.requireNonNull(c3786c0);
        }
        AbstractC3816m0 abstractC3816m0 = this;
        boolean z2 = false;
        while (true) {
            if (f.E(abstractC3816m0, obj, c3786c0)) {
                i(abstractC3816m0);
                if (!(obj instanceof RunnableC3798g0)) {
                    break;
                }
                InterfaceFutureC3845w0 interfaceFutureC3845w0 = ((RunnableC3798g0) obj).b;
                if (!(interfaceFutureC3845w0 instanceof InterfaceC3804i0)) {
                    interfaceFutureC3845w0.cancel(z);
                    break;
                }
                abstractC3816m0 = (AbstractC3816m0) interfaceFutureC3845w0;
                obj = abstractC3816m0.a;
                if (!(obj == null) && !(obj instanceof RunnableC3798g0)) {
                    break;
                }
                z2 = true;
            } else {
                obj = abstractC3816m0.a;
                if (!(obj instanceof RunnableC3798g0)) {
                    return z2;
                }
            }
        }
        return true;
    }

    public void d() {
    }

    public final void e(Throwable th) {
        if (f.E(this, null, new C3789d0(th))) {
            i(this);
        }
    }

    @Override // java.util.concurrent.Future
    public final Object get() throws InterruptedException {
        Object obj;
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }
        Object obj2 = this.a;
        if ((obj2 != null) && (!(obj2 instanceof RunnableC3798g0))) {
            return l(obj2);
        }
        C3813l0 c3813l0 = this.c;
        C3813l0 c3813l02 = C3813l0.c;
        if (c3813l0 != c3813l02) {
            C3813l0 c3813l03 = new C3813l0();
            do {
                Z0 z0 = f;
                z0.t(c3813l03, c3813l0);
                if (z0.G(this, c3813l0, c3813l03)) {
                    do {
                        LockSupport.park(this);
                        if (Thread.interrupted()) {
                            k(c3813l03);
                            throw new InterruptedException();
                        }
                        obj = this.a;
                    } while (!((obj != null) & (!(obj instanceof RunnableC3798g0))));
                    return l(obj);
                }
                c3813l0 = this.c;
            } while (c3813l0 != c3813l02);
        }
        Object obj3 = this.a;
        Objects.requireNonNull(obj3);
        return l(obj3);
    }

    public final void h(StringBuilder sb) {
        try {
            Object objG = g(this);
            sb.append("SUCCESS, result=[");
            if (objG == null) {
                sb.append("null");
            } else if (objG == this) {
                sb.append("this future");
            } else {
                sb.append(objG.getClass().getName());
                sb.append("@");
                sb.append(Integer.toHexString(System.identityHashCode(objG)));
            }
            sb.append("]");
        } catch (CancellationException unused) {
            sb.append("CANCELLED");
        } catch (ExecutionException e2) {
            sb.append("FAILURE, cause=[");
            sb.append(e2.getCause());
            sb.append("]");
        } catch (Exception e3) {
            sb.append("UNKNOWN, cause=[");
            sb.append(e3.getClass());
            sb.append(" thrown from get()]");
        }
    }

    @Override // java.util.concurrent.Future
    public final boolean isCancelled() {
        return this.a instanceof C3786c0;
    }

    @Override // java.util.concurrent.Future
    public final boolean isDone() {
        return (this.a != null) & (!(r0 instanceof RunnableC3798g0));
    }

    public final void k(C3813l0 c3813l0) {
        c3813l0.a = null;
        while (true) {
            C3813l0 c3813l02 = this.c;
            if (c3813l02 != C3813l0.c) {
                C3813l0 c3813l03 = null;
                while (c3813l02 != null) {
                    C3813l0 c3813l04 = c3813l02.b;
                    if (c3813l02.a != null) {
                        c3813l03 = c3813l02;
                    } else if (c3813l03 != null) {
                        c3813l03.b = c3813l04;
                        if (c3813l03.a == null) {
                            break;
                        }
                    } else if (!f.G(this, c3813l02, c3813l04)) {
                        break;
                    }
                    c3813l02 = c3813l04;
                }
                return;
            }
            return;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00c4  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String toString() {
        /*
            r6 = this;
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.Class r1 = r6.getClass()
            java.lang.String r1 = r1.getName()
            java.lang.String r2 = "com.google.common.util.concurrent."
            boolean r1 = r1.startsWith(r2)
            if (r1 == 0) goto L21
            java.lang.Class r1 = r6.getClass()
            java.lang.String r1 = r1.getSimpleName()
            r0.append(r1)
            goto L2c
        L21:
            java.lang.Class r1 = r6.getClass()
            java.lang.String r1 = r1.getName()
            r0.append(r1)
        L2c:
            r1 = 64
            r0.append(r1)
            int r1 = java.lang.System.identityHashCode(r6)
            java.lang.String r1 = java.lang.Integer.toHexString(r1)
            r0.append(r1)
            java.lang.String r1 = "[status="
            r0.append(r1)
            java.lang.Object r1 = r6.a
            boolean r1 = r1 instanceof com.google.android.gms.internal.play_billing.C3786c0
            java.lang.String r2 = "]"
            if (r1 == 0) goto L50
            java.lang.String r1 = "CANCELLED"
            r0.append(r1)
            goto Lce
        L50:
            boolean r1 = r6.isDone()
            if (r1 == 0) goto L5b
            r6.h(r0)
            goto Lce
        L5b:
            int r1 = r0.length()
            java.lang.String r3 = "PENDING"
            r0.append(r3)
            java.lang.Object r3 = r6.a
            boolean r4 = r3 instanceof com.google.android.gms.internal.play_billing.RunnableC3798g0
            java.lang.String r5 = "Exception thrown from implementation: "
            if (r4 == 0) goto L93
            java.lang.String r4 = ", setFuture=["
            r0.append(r4)
            com.google.android.gms.internal.play_billing.g0 r3 = (com.google.android.gms.internal.play_billing.RunnableC3798g0) r3
            com.google.android.gms.internal.play_billing.w0 r3 = r3.b
            if (r3 != r6) goto L81
            java.lang.String r3 = "this future"
            r0.append(r3)     // Catch: java.lang.StackOverflowError -> L7d java.lang.Exception -> L7f
            goto L8f
        L7d:
            r3 = move-exception
            goto L85
        L7f:
            r3 = move-exception
            goto L85
        L81:
            r0.append(r3)     // Catch: java.lang.StackOverflowError -> L7d java.lang.Exception -> L7f
            goto L8f
        L85:
            r0.append(r5)
            java.lang.Class r3 = r3.getClass()
            r0.append(r3)
        L8f:
            r0.append(r2)
            goto Lbe
        L93:
            java.lang.String r3 = r6.c()     // Catch: java.lang.StackOverflowError -> La2 java.lang.Exception -> La4
            r4 = 0
            if (r3 == 0) goto La0
            boolean r5 = r3.isEmpty()     // Catch: java.lang.StackOverflowError -> La2 java.lang.Exception -> La4
            if (r5 == 0) goto Lb1
        La0:
            r3 = r4
            goto Lb1
        La2:
            r3 = move-exception
            goto La5
        La4:
            r3 = move-exception
        La5:
            java.lang.Class r3 = r3.getClass()
            java.lang.String r3 = java.lang.String.valueOf(r3)
            java.lang.String r3 = r5.concat(r3)
        Lb1:
            if (r3 == 0) goto Lbe
            java.lang.String r4 = ", info=["
            r0.append(r4)
            r0.append(r3)
            r0.append(r2)
        Lbe:
            boolean r3 = r6.isDone()
            if (r3 == 0) goto Lce
            int r3 = r0.length()
            r0.delete(r1, r3)
            r6.h(r0)
        Lce:
            r0.append(r2)
            java.lang.String r0 = r0.toString()
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.AbstractC3816m0.toString():java.lang.String");
    }

    @Override // java.util.concurrent.Future
    public final Object get(long j, TimeUnit timeUnit) throws InterruptedException, TimeoutException {
        boolean z;
        long j2;
        long nanos = timeUnit.toNanos(j);
        if (!Thread.interrupted()) {
            Object obj = this.a;
            if ((obj != null) & (!(obj instanceof RunnableC3798g0))) {
                return l(obj);
            }
            long j3 = 0;
            long jNanoTime = nanos > 0 ? System.nanoTime() + nanos : 0L;
            if (nanos >= 1000) {
                C3813l0 c3813l0 = this.c;
                C3813l0 c3813l02 = C3813l0.c;
                if (c3813l0 != c3813l02) {
                    C3813l0 c3813l03 = new C3813l0();
                    z = true;
                    while (true) {
                        Z0 z0 = f;
                        z0.t(c3813l03, c3813l0);
                        if (z0.G(this, c3813l0, c3813l03)) {
                            j2 = j3;
                            do {
                                LockSupport.parkNanos(this, Math.min(nanos, 2147483647999999999L));
                                if (!Thread.interrupted()) {
                                    Object obj2 = this.a;
                                    if ((obj2 != null) & (!(obj2 instanceof RunnableC3798g0))) {
                                        return l(obj2);
                                    }
                                    nanos = jNanoTime - System.nanoTime();
                                } else {
                                    k(c3813l03);
                                    throw new InterruptedException();
                                }
                            } while (nanos >= 1000);
                            k(c3813l03);
                        } else {
                            long j4 = j3;
                            c3813l0 = this.c;
                            if (c3813l0 == c3813l02) {
                                break;
                            }
                            j3 = j4;
                        }
                    }
                }
                Object obj3 = this.a;
                Objects.requireNonNull(obj3);
                return l(obj3);
            }
            z = true;
            j2 = 0;
            while (nanos > j2) {
                Object obj4 = this.a;
                if ((obj4 != null ? z : false) & (!(obj4 instanceof RunnableC3798g0))) {
                    return l(obj4);
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
            if (nanos + 1000 < j2) {
                String strConcat2 = strConcat.concat(" (plus ");
                long j5 = -nanos;
                long jConvert = timeUnit.convert(j5, TimeUnit.NANOSECONDS);
                long nanos2 = j5 - timeUnit.toNanos(jConvert);
                if (jConvert != j2 && nanos2 <= 1000) {
                    z = false;
                }
                if (jConvert > j2) {
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
