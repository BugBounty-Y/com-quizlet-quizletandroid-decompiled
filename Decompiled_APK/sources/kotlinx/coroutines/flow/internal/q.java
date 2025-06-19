package kotlinx.coroutines.flow.internal;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public InterfaceC5002j j;
    public int k;
    public final /* synthetic */ kotlinx.coroutines.channels.t l;
    public final /* synthetic */ InterfaceC5002j m;
    public final /* synthetic */ com.quizlet.qutils.coroutines.a n;
    public final /* synthetic */ Object o;
    public final /* synthetic */ C5027k0 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(kotlinx.coroutines.channels.t tVar, InterfaceC5002j interfaceC5002j, com.quizlet.qutils.coroutines.a aVar, Object obj, C5027k0 c5027k0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = tVar;
        this.m = interfaceC5002j;
        this.n = aVar;
        this.o = obj;
        this.p = c5027k0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C5027k0 c5027k0 = this.p;
        return new q(this.l, this.m, this.n, this.o, c5027k0, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((Unit) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x0068, code lost:
    
        if (r1.emit(r7, r6) != r0) goto L30;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) throws java.lang.Throwable {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.k
            r2 = 0
            r3 = 3
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L2a
            if (r1 == r5) goto L22
            if (r1 == r4) goto L1c
            if (r1 != r3) goto L14
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L6b
        L14:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1c:
            kotlinx.coroutines.flow.j r1 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L60
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlinx.coroutines.channels.o r7 = (kotlinx.coroutines.channels.o) r7
            java.lang.Object r7 = r7.a
            goto L38
        L2a:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r6.k = r5
            kotlinx.coroutines.channels.t r7 = r6.l
            java.lang.Object r7 = r7.g(r6)
            if (r7 != r0) goto L38
            goto L6a
        L38:
            boolean r1 = r7 instanceof kotlinx.coroutines.channels.n
            if (r1 == 0) goto L4a
            java.lang.Throwable r7 = kotlinx.coroutines.channels.o.a(r7)
            if (r7 != 0) goto L49
            kotlinx.coroutines.flow.internal.AbortFlowException r7 = new kotlinx.coroutines.flow.internal.AbortFlowException
            kotlinx.coroutines.k0 r0 = r6.p
            r7.<init>(r0)
        L49:
            throw r7
        L4a:
            com.android.billingclient.api.a r1 = kotlinx.coroutines.flow.internal.AbstractC4994b.b
            if (r7 != r1) goto L4f
            r7 = r2
        L4f:
            kotlinx.coroutines.flow.j r1 = r6.m
            r6.j = r1
            r6.k = r4
            com.quizlet.qutils.coroutines.a r4 = r6.n
            java.lang.Object r5 = r6.o
            java.lang.Object r7 = r4.invoke(r5, r7, r6)
            if (r7 != r0) goto L60
            goto L6a
        L60:
            r6.j = r2
            r6.k = r3
            java.lang.Object r7 = r1.emit(r7, r6)
            if (r7 != r0) goto L6b
        L6a:
            return r0
        L6b:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.internal.q.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
