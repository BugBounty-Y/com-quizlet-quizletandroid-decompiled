package androidx.glance.session;

import android.content.Context;
import androidx.compose.runtime.C0832v0;
import androidx.compose.runtime.C0833w;
import androidx.glance.appwidget.C1182m;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class A extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Throwable j;
    public int k;
    public final /* synthetic */ C0833w l;
    public final /* synthetic */ C1182m m;
    public final /* synthetic */ Context n;
    public final /* synthetic */ C0832v0 o;
    public final /* synthetic */ K p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(C0833w c0833w, C1182m c1182m, Context context, C0832v0 c0832v0, K k, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0833w;
        this.m = c1182m;
        this.n = context;
        this.o = c0832v0;
        this.p = k;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new A(this.l, this.m, this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((A) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x0044, code lost:
    
        if (r9.H(r8) == r0) goto L19;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) throws java.lang.Throwable {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.k
            android.content.Context r2 = r8.n
            androidx.glance.appwidget.m r3 = r8.m
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L24
            if (r1 == r5) goto L1e
            if (r1 != r4) goto L16
            java.lang.Throwable r0 = r8.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L54
        L16:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L22 java.util.concurrent.CancellationException -> L5f
            goto L5f
        L22:
            r9 = move-exception
            goto L47
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            androidx.compose.runtime.w r9 = r8.l     // Catch: java.lang.Throwable -> L22 java.util.concurrent.CancellationException -> L5f
            r3.getClass()     // Catch: java.lang.Throwable -> L22 java.util.concurrent.CancellationException -> L5f
            androidx.glance.appwidget.k r1 = new androidx.glance.appwidget.k     // Catch: java.lang.Throwable -> L22 java.util.concurrent.CancellationException -> L5f
            r1.<init>(r2, r3)     // Catch: java.lang.Throwable -> L22 java.util.concurrent.CancellationException -> L5f
            androidx.compose.runtime.internal.d r6 = new androidx.compose.runtime.internal.d     // Catch: java.lang.Throwable -> L22 java.util.concurrent.CancellationException -> L5f
            r7 = -1784282257(0xffffffff95a6036f, float:-6.7052283E-26)
            r6.<init>(r5, r7, r1)     // Catch: java.lang.Throwable -> L22 java.util.concurrent.CancellationException -> L5f
            r9.m(r6)     // Catch: java.lang.Throwable -> L22 java.util.concurrent.CancellationException -> L5f
            androidx.compose.runtime.v0 r9 = r8.o     // Catch: java.lang.Throwable -> L22 java.util.concurrent.CancellationException -> L5f
            r8.k = r5     // Catch: java.lang.Throwable -> L22 java.util.concurrent.CancellationException -> L5f
            java.lang.Object r9 = r9.H(r8)     // Catch: java.lang.Throwable -> L22 java.util.concurrent.CancellationException -> L5f
            if (r9 != r0) goto L5f
            goto L52
        L47:
            r8.j = r9
            r8.k = r4
            r3.a(r2, r9)
            kotlin.Unit r1 = kotlin.Unit.a
            if (r1 != r0) goto L53
        L52:
            return r0
        L53:
            r0 = r9
        L54:
            java.lang.String r9 = "Error in recomposition coroutine"
            java.util.concurrent.CancellationException r9 = kotlinx.coroutines.E.a(r9, r0)
            androidx.glance.session.K r0 = r8.p
            kotlinx.coroutines.E.i(r0, r9)
        L5f:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.session.A.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
