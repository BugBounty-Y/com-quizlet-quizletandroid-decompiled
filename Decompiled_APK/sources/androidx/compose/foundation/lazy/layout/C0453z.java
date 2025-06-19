package androidx.compose.foundation.lazy.layout;

import androidx.compose.animation.core.C0253l0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.lazy.layout.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0453z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public androidx.compose.animation.core.D j;
    public int k;
    public final /* synthetic */ E l;
    public final /* synthetic */ C0253l0 m;
    public final /* synthetic */ long n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0453z(E e, C0253l0 c0253l0, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = e;
        this.m = c0253l0;
        this.n = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0453z(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0453z) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x0073, code lost:
    
        if (androidx.compose.animation.core.C0238e.c(r8, r9, r1, r11, r14, 4) != r0) goto L29;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r15) throws java.lang.Throwable {
        /*
            r14 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r14.k
            androidx.compose.foundation.lazy.layout.E r2 = r14.l
            long r3 = r14.n
            r5 = 2
            r6 = 1
            androidx.compose.animation.core.e r7 = r2.o
            if (r1 == 0) goto L24
            if (r1 == r6) goto L1e
            if (r1 != r5) goto L16
            androidx.glance.appwidget.protobuf.Z.e(r15)     // Catch: java.util.concurrent.CancellationException -> L7e
            goto L76
        L16:
            java.lang.IllegalStateException r15 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r15.<init>(r0)
            throw r15
        L1e:
            androidx.compose.animation.core.D r1 = r14.j
            androidx.glance.appwidget.protobuf.Z.e(r15)     // Catch: java.util.concurrent.CancellationException -> L7e
            goto L4a
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            boolean r15 = r7.e()     // Catch: java.util.concurrent.CancellationException -> L7e
            androidx.compose.animation.core.l0 r1 = r14.m
            if (r15 == 0) goto L34
            if (r1 == 0) goto L32
            goto L34
        L32:
            androidx.compose.animation.core.l0 r1 = androidx.compose.foundation.lazy.layout.F.a     // Catch: java.util.concurrent.CancellationException -> L7e
        L34:
            boolean r15 = r7.e()     // Catch: java.util.concurrent.CancellationException -> L7e
            if (r15 != 0) goto L4f
            androidx.compose.ui.unit.h r15 = new androidx.compose.ui.unit.h     // Catch: java.util.concurrent.CancellationException -> L7e
            r15.<init>(r3)     // Catch: java.util.concurrent.CancellationException -> L7e
            r14.j = r1     // Catch: java.util.concurrent.CancellationException -> L7e
            r14.k = r6     // Catch: java.util.concurrent.CancellationException -> L7e
            java.lang.Object r15 = r7.f(r15, r14)     // Catch: java.util.concurrent.CancellationException -> L7e
            if (r15 != r0) goto L4a
            goto L75
        L4a:
            androidx.compose.animation.core.K r15 = r2.c     // Catch: java.util.concurrent.CancellationException -> L7e
            r15.invoke()     // Catch: java.util.concurrent.CancellationException -> L7e
        L4f:
            r10 = r1
            java.lang.Object r15 = r7.d()     // Catch: java.util.concurrent.CancellationException -> L7e
            androidx.compose.ui.unit.h r15 = (androidx.compose.ui.unit.h) r15     // Catch: java.util.concurrent.CancellationException -> L7e
            long r6 = r15.a     // Catch: java.util.concurrent.CancellationException -> L7e
            long r3 = androidx.compose.ui.unit.h.c(r6, r3)     // Catch: java.util.concurrent.CancellationException -> L7e
            androidx.compose.animation.core.e r8 = r2.o     // Catch: java.util.concurrent.CancellationException -> L7e
            androidx.compose.ui.unit.h r9 = new androidx.compose.ui.unit.h     // Catch: java.util.concurrent.CancellationException -> L7e
            r9.<init>(r3)     // Catch: java.util.concurrent.CancellationException -> L7e
            androidx.compose.material.S r11 = new androidx.compose.material.S     // Catch: java.util.concurrent.CancellationException -> L7e
            r11.<init>(r2, r3)     // Catch: java.util.concurrent.CancellationException -> L7e
            r15 = 0
            r14.j = r15     // Catch: java.util.concurrent.CancellationException -> L7e
            r14.k = r5     // Catch: java.util.concurrent.CancellationException -> L7e
            r13 = 4
            r12 = r14
            java.lang.Object r15 = androidx.compose.animation.core.C0238e.c(r8, r9, r10, r11, r12, r13)     // Catch: java.util.concurrent.CancellationException -> L7e
            if (r15 != r0) goto L76
        L75:
            return r0
        L76:
            int r15 = androidx.compose.foundation.lazy.layout.E.t     // Catch: java.util.concurrent.CancellationException -> L7e
            r15 = 0
            r2.f(r15)     // Catch: java.util.concurrent.CancellationException -> L7e
            r2.g = r15     // Catch: java.util.concurrent.CancellationException -> L7e
        L7e:
            kotlin.Unit r15 = kotlin.Unit.a
            return r15
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.lazy.layout.C0453z.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
