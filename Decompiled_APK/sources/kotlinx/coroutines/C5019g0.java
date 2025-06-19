package kotlinx.coroutines;

import androidx.lifecycle.C1247h;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: kotlinx.coroutines.g0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5019g0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ C1247h k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5019g0(C1247h c1247h, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c1247h;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C5019g0 c5019g0 = new C5019g0(this.k, hVar);
        c5019g0.j = obj;
        return c5019g0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C5019g0) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x0041, code lost:
    
        return r0.invoke();
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0044, code lost:
    
        r5 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x0045, code lost:
    
        r1.l();
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x0048, code lost:
    
        throw r5;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r5) throws java.lang.Throwable {
        /*
            r4 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            androidx.glance.appwidget.protobuf.Z.e(r5)
            java.lang.Object r5 = r4.j
            kotlinx.coroutines.C r5 = (kotlinx.coroutines.C) r5
            kotlin.coroutines.CoroutineContext r5 = r5.getCoroutineContext()
            androidx.lifecycle.h r0 = r4.k
            kotlinx.coroutines.D0 r1 = new kotlinx.coroutines.D0     // Catch: java.lang.InterruptedException -> L42
            r1.<init>()     // Catch: java.lang.InterruptedException -> L42
            kotlinx.coroutines.j0 r5 = kotlinx.coroutines.E.s(r5)     // Catch: java.lang.InterruptedException -> L42
            r2 = 1
            kotlinx.coroutines.Q r5 = kotlinx.coroutines.E.v(r5, r2, r1)     // Catch: java.lang.InterruptedException -> L42
            r1.f = r5     // Catch: java.lang.InterruptedException -> L42
        L1f:
            java.util.concurrent.atomic.AtomicIntegerFieldUpdater r5 = kotlinx.coroutines.D0.g     // Catch: java.lang.InterruptedException -> L42
            int r2 = r5.get(r1)     // Catch: java.lang.InterruptedException -> L42
            if (r2 == 0) goto L33
            r5 = 2
            if (r2 == r5) goto L3a
            r5 = 3
            if (r2 != r5) goto L2e
            goto L3a
        L2e:
            kotlinx.coroutines.D0.m(r2)     // Catch: java.lang.InterruptedException -> L42
            r5 = 0
            throw r5     // Catch: java.lang.InterruptedException -> L42
        L33:
            r3 = 0
            boolean r5 = r5.compareAndSet(r1, r2, r3)     // Catch: java.lang.InterruptedException -> L42
            if (r5 == 0) goto L1f
        L3a:
            java.lang.Object r5 = r0.invoke()     // Catch: java.lang.Throwable -> L44
            r1.l()     // Catch: java.lang.InterruptedException -> L42
            return r5
        L42:
            r5 = move-exception
            goto L49
        L44:
            r5 = move-exception
            r1.l()     // Catch: java.lang.InterruptedException -> L42
            throw r5     // Catch: java.lang.InterruptedException -> L42
        L49:
            java.util.concurrent.CancellationException r0 = new java.util.concurrent.CancellationException
            java.lang.String r1 = "Blocking call was interrupted due to parent cancellation"
            r0.<init>(r1)
            java.lang.Throwable r5 = r0.initCause(r5)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.C5019g0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
