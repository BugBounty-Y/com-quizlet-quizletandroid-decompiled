package kotlinx.coroutines.flow;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.internal.AbstractC4993a;

/* loaded from: classes3.dex */
public final class Q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i0 k;
    public final /* synthetic */ InterfaceC4992i l;
    public final /* synthetic */ AbstractC4993a m;
    public final /* synthetic */ Object n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public Q(i0 i0Var, InterfaceC4992i interfaceC4992i, W w, Object obj, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = i0Var;
        this.l = interfaceC4992i;
        this.m = (AbstractC4993a) w;
        this.n = obj;
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [kotlinx.coroutines.flow.W, kotlinx.coroutines.flow.internal.a] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new Q(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Q) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x0036, code lost:
    
        if (r2.b(r3, r8) == r0) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x0056, code lost:
    
        if (r2.b(r3, r8) != r0) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0072, code lost:
    
        if (kotlinx.coroutines.flow.e0.i(r9, r1, r8) == r0) goto L28;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v0, types: [kotlinx.coroutines.flow.W, kotlinx.coroutines.flow.internal.a, kotlinx.coroutines.flow.j] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.j
            kotlinx.coroutines.flow.i r2 = r8.l
            kotlinx.coroutines.flow.internal.a r3 = r8.m
            r4 = 4
            r5 = 3
            r6 = 1
            r7 = 2
            if (r1 == 0) goto L27
            if (r1 == r6) goto L23
            if (r1 == r7) goto L1f
            if (r1 == r5) goto L23
            if (r1 != r4) goto L17
            goto L23
        L17:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L50
        L23:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L75
        L27:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlinx.coroutines.flow.j0 r9 = kotlinx.coroutines.flow.h0.a
            kotlinx.coroutines.flow.i0 r1 = r8.k
            if (r1 != r9) goto L39
            r8.j = r6
            java.lang.Object r9 = r2.b(r3, r8)
            if (r9 != r0) goto L75
            goto L74
        L39:
            kotlinx.coroutines.flow.j0 r9 = kotlinx.coroutines.flow.h0.b
            r6 = 0
            if (r1 != r9) goto L59
            kotlinx.coroutines.flow.internal.H r9 = r3.j()
            kotlinx.coroutines.flow.O r1 = new kotlinx.coroutines.flow.O
            r1.<init>(r7, r6)
            r8.j = r7
            java.lang.Object r9 = kotlinx.coroutines.flow.e0.q(r9, r1, r8)
            if (r9 != r0) goto L50
            goto L74
        L50:
            r8.j = r5
            java.lang.Object r9 = r2.b(r3, r8)
            if (r9 != r0) goto L75
            goto L74
        L59:
            kotlinx.coroutines.flow.internal.H r9 = r3.j()
            kotlinx.coroutines.flow.i r9 = r1.a(r9)
            kotlinx.coroutines.flow.i r9 = kotlinx.coroutines.flow.e0.m(r9)
            kotlinx.coroutines.flow.P r1 = new kotlinx.coroutines.flow.P
            java.lang.Object r5 = r8.n
            r1.<init>(r2, r3, r5, r6)
            r8.j = r4
            java.lang.Object r9 = kotlinx.coroutines.flow.e0.i(r9, r1, r8)
            if (r9 != r0) goto L75
        L74:
            return r0
        L75:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.Q.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
