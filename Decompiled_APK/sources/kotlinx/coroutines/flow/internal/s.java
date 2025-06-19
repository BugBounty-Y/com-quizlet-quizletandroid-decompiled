package kotlinx.coroutines.flow.internal;

import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class s implements InterfaceC5002j {
    public final /* synthetic */ CoroutineContext a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ kotlinx.coroutines.channels.t c;
    public final /* synthetic */ InterfaceC5002j d;
    public final /* synthetic */ com.quizlet.qutils.coroutines.a e;
    public final /* synthetic */ C5027k0 f;

    public s(CoroutineContext coroutineContext, Object obj, kotlinx.coroutines.channels.t tVar, InterfaceC5002j interfaceC5002j, com.quizlet.qutils.coroutines.a aVar, C5027k0 c5027k0) {
        this.a = coroutineContext;
        this.b = obj;
        this.c = tVar;
        this.d = interfaceC5002j;
        this.e = aVar;
        this.f = c5027k0;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object emit(java.lang.Object r12, kotlin.coroutines.h r13) {
        /*
            r11 = this;
            boolean r0 = r13 instanceof kotlinx.coroutines.flow.internal.r
            if (r0 == 0) goto L13
            r0 = r13
            kotlinx.coroutines.flow.internal.r r0 = (kotlinx.coroutines.flow.internal.r) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.internal.r r0 = new kotlinx.coroutines.flow.internal.r
            r0.<init>(r11, r13)
        L18:
            java.lang.Object r13 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L50
        L27:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r13 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r13)
            throw r12
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            kotlin.Unit r13 = kotlin.Unit.a
            kotlinx.coroutines.flow.internal.q r4 = new kotlinx.coroutines.flow.internal.q
            kotlinx.coroutines.k0 r9 = r11.f
            kotlinx.coroutines.channels.t r5 = r11.c
            com.quizlet.qutils.coroutines.a r7 = r11.e
            kotlinx.coroutines.flow.j r6 = r11.d
            r10 = 0
            r8 = r12
            r4.<init>(r5, r6, r7, r8, r9, r10)
            r0.l = r3
            kotlin.coroutines.CoroutineContext r12 = r11.a
            java.lang.Object r2 = r11.b
            java.lang.Object r12 = kotlinx.coroutines.flow.internal.AbstractC4994b.c(r12, r13, r2, r4, r0)
            if (r12 != r1) goto L50
            return r1
        L50:
            kotlin.Unit r12 = kotlin.Unit.a
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.internal.s.emit(java.lang.Object, kotlin.coroutines.h):java.lang.Object");
    }
}
