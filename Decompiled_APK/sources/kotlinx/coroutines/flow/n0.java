package kotlinx.coroutines.flow;

import kotlin.Unit;

/* loaded from: classes3.dex */
public final class n0 extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public int j;
    public /* synthetic */ InterfaceC5002j k;
    public /* synthetic */ int l;
    public final /* synthetic */ p0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n0(p0 p0Var, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.m = p0Var;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        int iIntValue = ((Number) obj2).intValue();
        n0 n0Var = new n0(this.m, (kotlin.coroutines.h) obj3);
        n0Var.k = (InterfaceC5002j) obj;
        n0Var.l = iIntValue;
        return n0Var.invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0047, code lost:
    
        if (r1.emit(r11, r10) == r0) goto L32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x0085, code lost:
    
        if (r1.emit(r11, r10) != r0) goto L33;
     */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0067 A[PHI: r1
  0x0067: PHI (r1v3 kotlinx.coroutines.flow.j) = (r1v2 kotlinx.coroutines.flow.j), (r1v6 kotlinx.coroutines.flow.j) binds: [B:25:0x0064, B:13:0x0026] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x007a A[PHI: r1
  0x007a: PHI (r1v4 kotlinx.coroutines.flow.j) = (r1v3 kotlinx.coroutines.flow.j), (r1v7 kotlinx.coroutines.flow.j) binds: [B:28:0x0077, B:12:0x0020] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r11) {
        /*
            r10 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r10.j
            r2 = 5
            r3 = 4
            r4 = 3
            r5 = 2
            r6 = 1
            kotlinx.coroutines.flow.p0 r7 = r10.m
            if (r1 == 0) goto L36
            if (r1 == r6) goto L32
            if (r1 == r5) goto L2c
            if (r1 == r4) goto L26
            if (r1 == r3) goto L20
            if (r1 != r2) goto L18
            goto L32
        L18:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L20:
            kotlinx.coroutines.flow.j r1 = r10.k
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L7a
        L26:
            kotlinx.coroutines.flow.j r1 = r10.k
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L67
        L2c:
            kotlinx.coroutines.flow.j r1 = r10.k
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L57
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L88
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            kotlinx.coroutines.flow.j r1 = r10.k
            int r11 = r10.l
            if (r11 <= 0) goto L4a
            kotlinx.coroutines.flow.g0 r11 = kotlinx.coroutines.flow.g0.a
            r10.j = r6
            java.lang.Object r11 = r1.emit(r11, r10)
            if (r11 != r0) goto L88
            goto L87
        L4a:
            long r8 = r7.a
            r10.k = r1
            r10.j = r5
            java.lang.Object r11 = kotlinx.coroutines.E.n(r8, r10)
            if (r11 != r0) goto L57
            goto L87
        L57:
            r7.getClass()
            kotlinx.coroutines.flow.g0 r11 = kotlinx.coroutines.flow.g0.b
            r10.k = r1
            r10.j = r4
            java.lang.Object r11 = r1.emit(r11, r10)
            if (r11 != r0) goto L67
            goto L87
        L67:
            r7.getClass()
            r10.k = r1
            r10.j = r3
            r3 = 9223372036854775807(0x7fffffffffffffff, double:NaN)
            java.lang.Object r11 = kotlinx.coroutines.E.n(r3, r10)
            if (r11 != r0) goto L7a
            goto L87
        L7a:
            kotlinx.coroutines.flow.g0 r11 = kotlinx.coroutines.flow.g0.c
            r3 = 0
            r10.k = r3
            r10.j = r2
            java.lang.Object r11 = r1.emit(r11, r10)
            if (r11 != r0) goto L88
        L87:
            return r0
        L88:
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.n0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
