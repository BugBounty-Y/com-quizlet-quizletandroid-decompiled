package kotlinx.coroutines.internal;

import com.android.billingclient.api.C1472a;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.C4937f;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.text.StringsKt;
import kotlinx.coroutines.A;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.DispatchException;

/* loaded from: classes3.dex */
public abstract class b {
    public static final C1472a a = new C1472a("CLOSED", 2);
    public static final C1472a b = new C1472a("UNDEFINED", 2);
    public static final C1472a c = new C1472a("REUSABLE_CLAIMED", 2);

    public static final void a(int i) {
        if (i < 1) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Expected positive parallelism level, but got ").toString());
        }
    }

    public static final Object b(q qVar, long j, Function2 function2) {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater;
        while (true) {
            if (qVar.c >= j && !qVar.d()) {
                return qVar;
            }
            Object obj = c.a.get(qVar);
            C1472a c1472a = a;
            if (obj == c1472a) {
                return c1472a;
            }
            q qVar2 = (q) ((c) obj);
            if (qVar2 == null) {
                qVar2 = (q) function2.invoke(Long.valueOf(qVar.c + 1), qVar);
                do {
                    atomicReferenceFieldUpdater = c.a;
                    if (atomicReferenceFieldUpdater.compareAndSet(qVar, null, qVar2)) {
                        if (qVar.d()) {
                            qVar.e();
                        }
                    }
                } while (atomicReferenceFieldUpdater.get(qVar) == null);
            }
            qVar = qVar2;
        }
    }

    public static final q c(Object obj) {
        if (obj != a) {
            return (q) obj;
        }
        throw new IllegalStateException("Does not contain segment");
    }

    public static final void d(CoroutineContext coroutineContext, Throwable th) {
        Throwable runtimeException;
        Iterator it2 = e.a.iterator();
        while (it2.hasNext()) {
            try {
                ((A) it2.next()).handleException(coroutineContext, th);
            } catch (ExceptionSuccessfullyProcessed unused) {
                return;
            } catch (Throwable th2) {
                if (th == th2) {
                    runtimeException = th;
                } else {
                    runtimeException = new RuntimeException("Exception while trying to handle coroutine exception", th2);
                    C4937f.a(runtimeException, th);
                }
                Thread threadCurrentThread = Thread.currentThread();
                threadCurrentThread.getUncaughtExceptionHandler().uncaughtException(threadCurrentThread, runtimeException);
            }
        }
        try {
            C4937f.a(th, new DiagnosticCoroutineContextException(coroutineContext));
        } catch (Throwable unused2) {
        }
        Thread threadCurrentThread2 = Thread.currentThread();
        threadCurrentThread2.getUncaughtExceptionHandler().uncaughtException(threadCurrentThread2, th);
    }

    public static final boolean e(Object obj) {
        return obj == a;
    }

    public static final Object f(Object obj, Object obj2) {
        if (obj == null) {
            return obj2;
        }
        if (obj instanceof ArrayList) {
            ((ArrayList) obj).add(obj2);
            return obj;
        }
        ArrayList arrayList = new ArrayList(4);
        arrayList.add(obj);
        arrayList.add(obj2);
        return arrayList;
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x008e A[Catch: all -> 0x006b, DONT_GENERATE, TryCatch #1 {all -> 0x006b, blocks: (B:16:0x004b, B:18:0x0059, B:20:0x005f, B:33:0x0091, B:23:0x006d, B:25:0x007b, B:30:0x0088, B:32:0x008e, B:38:0x009e, B:41:0x00a7, B:40:0x00a4, B:28:0x0081), top: B:52:0x004b, inners: #0 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void g(java.lang.Object r8, kotlin.coroutines.h r9) throws kotlinx.coroutines.DispatchException {
        /*
            boolean r0 = r9 instanceof kotlinx.coroutines.internal.f
            if (r0 == 0) goto Lb2
            kotlinx.coroutines.internal.f r9 = (kotlinx.coroutines.internal.f) r9
            java.lang.Throwable r0 = kotlin.r.a(r8)
            if (r0 != 0) goto Le
            r1 = r8
            goto L14
        Le:
            kotlinx.coroutines.u r1 = new kotlinx.coroutines.u
            r2 = 0
            r1.<init>(r0, r2)
        L14:
            kotlinx.coroutines.y r0 = r9.d
            kotlin.coroutines.jvm.internal.c r2 = r9.e
            kotlin.coroutines.CoroutineContext r3 = r2.getContext()
            boolean r0 = i(r0, r3)
            r3 = 1
            if (r0 == 0) goto L31
            r9.f = r1
            r9.c = r3
            kotlin.coroutines.CoroutineContext r8 = r2.getContext()
            kotlinx.coroutines.y r0 = r9.d
            h(r0, r8, r9)
            return
        L31:
            kotlinx.coroutines.Z r0 = kotlinx.coroutines.C0.a()
            long r4 = r0.b
            r6 = 4294967296(0x100000000, double:2.121995791E-314)
            int r4 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r4 < 0) goto L48
            r9.f = r1
            r9.c = r3
            r0.l0(r9)
            goto Lac
        L48:
            r0.n0(r3)
            kotlin.coroutines.CoroutineContext r1 = r2.getContext()     // Catch: java.lang.Throwable -> L6b
            kotlinx.coroutines.i0 r4 = kotlinx.coroutines.C5023i0.a     // Catch: java.lang.Throwable -> L6b
            kotlin.coroutines.CoroutineContext$Element r1 = r1.get(r4)     // Catch: java.lang.Throwable -> L6b
            kotlinx.coroutines.j0 r1 = (kotlinx.coroutines.InterfaceC5025j0) r1     // Catch: java.lang.Throwable -> L6b
            if (r1 == 0) goto L6d
            boolean r4 = r1.a()     // Catch: java.lang.Throwable -> L6b
            if (r4 != 0) goto L6d
            java.util.concurrent.CancellationException r8 = r1.y()     // Catch: java.lang.Throwable -> L6b
            kotlin.q r8 = androidx.glance.appwidget.protobuf.Z.b(r8)     // Catch: java.lang.Throwable -> L6b
            r9.resumeWith(r8)     // Catch: java.lang.Throwable -> L6b
            goto L91
        L6b:
            r8 = move-exception
            goto La8
        L6d:
            java.lang.Object r1 = r9.g     // Catch: java.lang.Throwable -> L6b
            kotlin.coroutines.CoroutineContext r4 = r2.getContext()     // Catch: java.lang.Throwable -> L6b
            java.lang.Object r1 = kotlinx.coroutines.internal.t.c(r4, r1)     // Catch: java.lang.Throwable -> L6b
            com.android.billingclient.api.a r5 = kotlinx.coroutines.internal.t.a     // Catch: java.lang.Throwable -> L6b
            if (r1 == r5) goto L80
            kotlinx.coroutines.H0 r5 = kotlinx.coroutines.AbstractC5038w.c(r2, r4, r1)     // Catch: java.lang.Throwable -> L6b
            goto L81
        L80:
            r5 = 0
        L81:
            r2.resumeWith(r8)     // Catch: java.lang.Throwable -> L9b
            kotlin.Unit r8 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L9b
            if (r5 == 0) goto L8e
            boolean r8 = r5.o0()     // Catch: java.lang.Throwable -> L6b
            if (r8 == 0) goto L91
        L8e:
            kotlinx.coroutines.internal.t.a(r4, r1)     // Catch: java.lang.Throwable -> L6b
        L91:
            boolean r8 = r0.p0()     // Catch: java.lang.Throwable -> L6b
            if (r8 != 0) goto L91
        L97:
            r0.k0(r3)
            goto Lac
        L9b:
            r8 = move-exception
            if (r5 == 0) goto La4
            boolean r2 = r5.o0()     // Catch: java.lang.Throwable -> L6b
            if (r2 == 0) goto La7
        La4:
            kotlinx.coroutines.internal.t.a(r4, r1)     // Catch: java.lang.Throwable -> L6b
        La7:
            throw r8     // Catch: java.lang.Throwable -> L6b
        La8:
            r9.g(r8)     // Catch: java.lang.Throwable -> Lad
            goto L97
        Lac:
            return
        Lad:
            r8 = move-exception
            r0.k0(r3)
            throw r8
        Lb2:
            r9.resumeWith(r8)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.internal.b.g(java.lang.Object, kotlin.coroutines.h):void");
    }

    public static final void h(AbstractC5040y abstractC5040y, CoroutineContext coroutineContext, Runnable runnable) throws DispatchException {
        try {
            abstractC5040y.r(coroutineContext, runnable);
        } catch (Throwable th) {
            throw new DispatchException(th, abstractC5040y, coroutineContext);
        }
    }

    public static final boolean i(AbstractC5040y abstractC5040y, CoroutineContext coroutineContext) throws DispatchException {
        try {
            return abstractC5040y.a0(coroutineContext);
        } catch (Throwable th) {
            throw new DispatchException(th, abstractC5040y, coroutineContext);
        }
    }

    public static final long j(String str, long j, long j2, long j3) {
        String property;
        int i = s.a;
        try {
            property = System.getProperty(str);
        } catch (SecurityException unused) {
            property = null;
        }
        if (property == null) {
            return j;
        }
        Long lF0 = StringsKt.f0(property);
        if (lF0 == null) {
            throw new IllegalStateException(("System property '" + str + "' has unrecognized value '" + property + '\'').toString());
        }
        long jLongValue = lF0.longValue();
        if (j2 <= jLongValue && jLongValue <= j3) {
            return jLongValue;
        }
        throw new IllegalStateException(("System property '" + str + "' should be in range " + j2 + ".." + j3 + ", but is '" + jLongValue + '\'').toString());
    }

    public static int k(int i, int i2, String str) {
        return (int) j(str, i, 1, (i2 & 8) != 0 ? SubsamplingScaleImageView.TILE_SIZE_AUTO : 2097150);
    }
}
