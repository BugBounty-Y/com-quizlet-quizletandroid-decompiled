package com.google.android.gms.internal.ads;

import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.LockSupport;
import java.util.logging.Level;

/* renamed from: com.google.android.gms.internal.ads.ov, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2460ov extends AbstractC2674tv {
    /* JADX WARN: Multi-variable type inference failed */
    public static Object i(com.google.common.util.concurrent.e eVar) {
        Throwable thC;
        if (eVar instanceof InterfaceC2374mv) {
            Object c2160hv = ((AbstractC2460ov) eVar).a;
            if (c2160hv instanceof C2160hv) {
                C2160hv c2160hv2 = (C2160hv) c2160hv;
                if (c2160hv2.a) {
                    RuntimeException runtimeException = c2160hv2.b;
                    c2160hv = runtimeException != null ? new C2160hv(false, runtimeException) : C2160hv.d;
                }
            }
            Objects.requireNonNull(c2160hv);
            return c2160hv;
        }
        if ((eVar instanceof AbstractC2246jw) && (thC = ((AbstractC2246jw) eVar).c()) != null) {
            return new C2288kv(thC);
        }
        boolean zIsCancelled = eVar.isCancelled();
        if ((!AbstractC2674tv.f) && zIsCancelled) {
            C2160hv c2160hv3 = C2160hv.d;
            Objects.requireNonNull(c2160hv3);
            return c2160hv3;
        }
        try {
            try {
                try {
                    Object objJ = j(eVar);
                    return zIsCancelled ? new C2160hv(false, new IllegalArgumentException("get() did not throw CancellationException, despite reporting isCancelled() == true: ".concat(String.valueOf(eVar)))) : objJ == null ? AbstractC2674tv.d : objJ;
                } catch (Error | Exception e) {
                    e = e;
                    return new C2288kv(e);
                }
            } catch (Error e2) {
                e = e2;
                return new C2288kv(e);
            }
        } catch (CancellationException e3) {
            return !zIsCancelled ? new C2288kv(new IllegalArgumentException("get() threw CancellationException, despite reporting isCancelled() == false: ".concat(String.valueOf(eVar)), e3)) : new C2160hv(false, e3);
        } catch (ExecutionException e4) {
            return zIsCancelled ? new C2160hv(false, new IllegalArgumentException("get() did not throw CancellationException, despite reporting isCancelled() == true: ".concat(String.valueOf(eVar)), e4)) : new C2288kv(e4.getCause());
        }
    }

    public static Object j(com.google.common.util.concurrent.e eVar) {
        Object obj;
        boolean z = false;
        while (true) {
            try {
                obj = eVar.get();
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

    public static Object k(Object obj) throws ExecutionException {
        if (obj instanceof C2160hv) {
            RuntimeException runtimeException = ((C2160hv) obj).b;
            CancellationException cancellationException = new CancellationException("Task was cancelled.");
            cancellationException.initCause(runtimeException);
            throw cancellationException;
        }
        if (obj instanceof C2288kv) {
            throw new ExecutionException(((C2288kv) obj).a);
        }
        if (obj == AbstractC2674tv.d) {
            return null;
        }
        return obj;
    }

    public static boolean n(Object obj) {
        return !(obj instanceof RunnableC2202iv);
    }

    public static void r(AbstractC2460ov abstractC2460ov, boolean z) {
        C2331lv c2331lv = null;
        while (true) {
            abstractC2460ov.getClass();
            for (C2631sv c2631svP = AbstractC2674tv.g.p(abstractC2460ov); c2631svP != null; c2631svP = c2631svP.b) {
                Thread thread = c2631svP.a;
                if (thread != null) {
                    c2631svP.a = null;
                    LockSupport.unpark(thread);
                }
            }
            if (z) {
                abstractC2460ov.l();
            }
            abstractC2460ov.f();
            C2331lv c2331lv2 = c2331lv;
            C2331lv c2331lvF = AbstractC2674tv.g.f(abstractC2460ov);
            C2331lv c2331lv3 = c2331lv2;
            while (c2331lvF != null) {
                C2331lv c2331lv4 = c2331lvF.c;
                c2331lvF.c = c2331lv3;
                c2331lv3 = c2331lvF;
                c2331lvF = c2331lv4;
            }
            while (c2331lv3 != null) {
                Runnable runnable = c2331lv3.a;
                c2331lv = c2331lv3.c;
                Objects.requireNonNull(runnable);
                if (runnable instanceof RunnableC2202iv) {
                    RunnableC2202iv runnableC2202iv = (RunnableC2202iv) runnable;
                    abstractC2460ov = runnableC2202iv.a;
                    if (abstractC2460ov.a == runnableC2202iv) {
                        if (AbstractC2674tv.g.z(abstractC2460ov, runnableC2202iv, i(runnableC2202iv.b))) {
                            break;
                        }
                    } else {
                        continue;
                    }
                } else {
                    Executor executor = c2331lv3.b;
                    Objects.requireNonNull(executor);
                    s(runnable, executor);
                }
                c2331lv3 = c2331lv;
            }
            return;
            z = false;
        }
    }

    public static void s(Runnable runnable, Executor executor) {
        try {
            executor.execute(runnable);
        } catch (Exception e) {
            AbstractC2674tv.e.a().logp(Level.SEVERE, "com.google.common.util.concurrent.AbstractFuture", "executeListener", android.support.v4.media.session.a.m("RuntimeException while executing runnable ", String.valueOf(runnable), " with executor ", String.valueOf(executor)), (Throwable) e);
        }
    }

    public void a(Runnable runnable, Executor executor) {
        C2331lv c2331lv;
        C2331lv c2331lv2;
        AbstractC1981ds.x(runnable, "Runnable was null.");
        AbstractC1981ds.x(executor, "Executor was null.");
        if (!isDone() && (c2331lv = this.b) != (c2331lv2 = C2331lv.d)) {
            C2331lv c2331lv3 = new C2331lv(runnable, executor);
            do {
                c2331lv3.c = c2331lv;
                if (AbstractC2674tv.g.y(this, c2331lv, c2331lv3)) {
                    return;
                } else {
                    c2331lv = this.b;
                }
            } while (c2331lv != c2331lv2);
        }
        s(runnable, executor);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2246jw
    public final Throwable c() {
        if (!(this instanceof InterfaceC2374mv)) {
            return null;
        }
        Object obj = this.a;
        if (obj instanceof C2288kv) {
            return ((C2288kv) obj).a;
        }
        return null;
    }

    public boolean cancel(boolean z) {
        C2160hv c2160hv;
        Object obj = this.a;
        if (!(obj instanceof RunnableC2202iv) && !(obj == null)) {
            return false;
        }
        if (AbstractC2674tv.f) {
            c2160hv = new C2160hv(z, new CancellationException("Future.cancel() was called."));
        } else {
            c2160hv = z ? C2160hv.c : C2160hv.d;
            Objects.requireNonNull(c2160hv);
        }
        AbstractC2460ov abstractC2460ov = this;
        boolean z2 = false;
        while (true) {
            if (AbstractC2674tv.g.z(abstractC2460ov, obj, c2160hv)) {
                r(abstractC2460ov, z);
                if (!(obj instanceof RunnableC2202iv)) {
                    break;
                }
                com.google.common.util.concurrent.e eVar = ((RunnableC2202iv) obj).b;
                if (!(eVar instanceof InterfaceC2374mv)) {
                    eVar.cancel(z);
                    break;
                }
                abstractC2460ov = (AbstractC2460ov) eVar;
                obj = abstractC2460ov.a;
                if (!(obj == null) && !(obj instanceof RunnableC2202iv)) {
                    break;
                }
                z2 = true;
            } else {
                obj = abstractC2460ov.a;
                if (n(obj)) {
                    return z2;
                }
            }
        }
        return true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public String e() {
        if (this instanceof ScheduledFuture) {
            return androidx.compose.animation.d0.o(((ScheduledFuture) this).getDelay(TimeUnit.MILLISECONDS), "remaining delay=[", " ms]");
        }
        return null;
    }

    public void f() {
    }

    public boolean g(Object obj) {
        if (obj == null) {
            obj = AbstractC2674tv.d;
        }
        if (!AbstractC2674tv.g.z(this, null, obj)) {
            return false;
        }
        r(this, false);
        return true;
    }

    public Object get() throws InterruptedException {
        Object obj;
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }
        Object obj2 = this.a;
        if ((obj2 != null) && n(obj2)) {
            return k(obj2);
        }
        C2631sv c2631sv = this.c;
        C2631sv c2631sv2 = C2631sv.c;
        if (c2631sv != c2631sv2) {
            C2631sv c2631sv3 = new C2631sv();
            do {
                AbstractC2457os abstractC2457os = AbstractC2674tv.g;
                abstractC2457os.t(c2631sv3, c2631sv);
                if (abstractC2457os.A(this, c2631sv, c2631sv3)) {
                    do {
                        LockSupport.park(this);
                        if (Thread.interrupted()) {
                            d(c2631sv3);
                            throw new InterruptedException();
                        }
                        obj = this.a;
                    } while (!((obj != null) & n(obj)));
                    return k(obj);
                }
                c2631sv = this.c;
            } while (c2631sv != c2631sv2);
        }
        Object obj3 = this.a;
        Objects.requireNonNull(obj3);
        return k(obj3);
    }

    public boolean h(Throwable th) {
        th.getClass();
        if (!AbstractC2674tv.g.z(this, null, new C2288kv(th))) {
            return false;
        }
        r(this, false);
        return true;
    }

    public boolean isCancelled() {
        return this.a instanceof C2160hv;
    }

    public boolean isDone() {
        Object obj = this.a;
        return (obj != null) & n(obj);
    }

    public void l() {
    }

    public final void m(Future future) {
        if ((future != null) && (this.a instanceof C2160hv)) {
            future.cancel(p());
        }
    }

    public final void o(com.google.common.util.concurrent.e eVar) {
        C2288kv c2288kv;
        eVar.getClass();
        Object obj = this.a;
        if (obj == null) {
            if (eVar.isDone()) {
                if (AbstractC2674tv.g.z(this, null, i(eVar))) {
                    r(this, false);
                    return;
                }
                return;
            }
            RunnableC2202iv runnableC2202iv = new RunnableC2202iv(this, eVar);
            if (AbstractC2674tv.g.z(this, null, runnableC2202iv)) {
                try {
                    eVar.a(runnableC2202iv, Kv.a);
                    return;
                } catch (Throwable th) {
                    try {
                        c2288kv = new C2288kv(th);
                    } catch (Error | Exception unused) {
                        c2288kv = C2288kv.b;
                    }
                    AbstractC2674tv.g.z(this, runnableC2202iv, c2288kv);
                    return;
                }
            }
            obj = this.a;
        }
        if (obj instanceof C2160hv) {
            eVar.cancel(((C2160hv) obj).a);
        }
    }

    public final boolean p() {
        Object obj = this.a;
        return (obj instanceof C2160hv) && ((C2160hv) obj).a;
    }

    public final void q(StringBuilder sb) {
        try {
            Object objJ = j(this);
            sb.append("SUCCESS, result=[");
            if (objJ == null) {
                sb.append("null");
            } else if (objJ == this) {
                sb.append("this future");
            } else {
                sb.append(objJ.getClass().getName());
                sb.append("@");
                sb.append(Integer.toHexString(System.identityHashCode(objJ)));
            }
            sb.append("]");
        } catch (CancellationException unused) {
            sb.append("CANCELLED");
        } catch (ExecutionException e) {
            sb.append("FAILURE, cause=[");
            sb.append(e.getCause());
            sb.append("]");
        } catch (Exception e2) {
            sb.append("UNKNOWN, cause=[");
            sb.append(e2.getClass());
            sb.append(" thrown from get()]");
        }
    }

    public String toString() {
        String strConcat;
        StringBuilder sb = new StringBuilder();
        if (getClass().getName().startsWith("com.google.common.util.concurrent.")) {
            sb.append(getClass().getSimpleName());
        } else {
            sb.append(getClass().getName());
        }
        sb.append('@');
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append("[status=");
        if (isCancelled()) {
            sb.append("CANCELLED");
        } else if (isDone()) {
            q(sb);
        } else {
            int length = sb.length();
            sb.append("PENDING");
            Object obj = this.a;
            if (obj instanceof RunnableC2202iv) {
                sb.append(", setFuture=[");
                com.google.common.util.concurrent.e eVar = ((RunnableC2202iv) obj).b;
                try {
                    if (eVar == this) {
                        sb.append("this future");
                    } else {
                        sb.append(eVar);
                    }
                } catch (Throwable th) {
                    if ((th instanceof Error) && !(th instanceof StackOverflowError)) {
                        throw th;
                    }
                    sb.append("Exception thrown from implementation: ");
                    sb.append(th.getClass());
                }
                sb.append("]");
            } else {
                try {
                    strConcat = e();
                    if (AbstractC2543qs.i(strConcat)) {
                        strConcat = null;
                    }
                } catch (Throwable th2) {
                    if ((th2 instanceof Error) && !(th2 instanceof StackOverflowError)) {
                        throw th2;
                    }
                    strConcat = "Exception thrown from implementation: ".concat(String.valueOf(th2.getClass()));
                }
                if (strConcat != null) {
                    sb.append(", info=[");
                    sb.append(strConcat);
                    sb.append("]");
                }
            }
            if (isDone()) {
                sb.delete(length, sb.length());
                q(sb);
            }
        }
        sb.append("]");
        return sb.toString();
    }

    public Object get(long j, TimeUnit timeUnit) throws InterruptedException, TimeoutException {
        long j2;
        long nanos = timeUnit.toNanos(j);
        if (!Thread.interrupted()) {
            Object obj = this.a;
            if ((obj != null) & n(obj)) {
                return k(obj);
            }
            long j3 = 0;
            long jNanoTime = nanos > 0 ? System.nanoTime() + nanos : 0L;
            if (nanos >= 1000) {
                C2631sv c2631sv = this.c;
                C2631sv c2631sv2 = C2631sv.c;
                if (c2631sv != c2631sv2) {
                    C2631sv c2631sv3 = new C2631sv();
                    while (true) {
                        AbstractC2457os abstractC2457os = AbstractC2674tv.g;
                        abstractC2457os.t(c2631sv3, c2631sv);
                        if (abstractC2457os.A(this, c2631sv, c2631sv3)) {
                            j2 = j3;
                            do {
                                LockSupport.parkNanos(this, Math.min(nanos, 2147483647999999999L));
                                if (!Thread.interrupted()) {
                                    Object obj2 = this.a;
                                    if ((obj2 != null) & n(obj2)) {
                                        return k(obj2);
                                    }
                                    nanos = jNanoTime - System.nanoTime();
                                } else {
                                    d(c2631sv3);
                                    throw new InterruptedException();
                                }
                            } while (nanos >= 1000);
                            d(c2631sv3);
                        } else {
                            long j4 = j3;
                            c2631sv = this.c;
                            if (c2631sv == c2631sv2) {
                                break;
                            }
                            j3 = j4;
                        }
                    }
                }
                Object obj3 = this.a;
                Objects.requireNonNull(obj3);
                return k(obj3);
            }
            j2 = 0;
            while (nanos > j2) {
                Object obj4 = this.a;
                if ((obj4 != null) & n(obj4)) {
                    return k(obj4);
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
                boolean z = jConvert == j2 || nanos2 > 1000;
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
