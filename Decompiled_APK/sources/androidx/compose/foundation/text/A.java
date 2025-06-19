package androidx.compose.foundation.text;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class A extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.foundation.text.selection.i0 a;
    public final /* synthetic */ C0492h0 b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ kotlin.jvm.internal.r e;
    public final /* synthetic */ androidx.compose.ui.text.input.A f;
    public final /* synthetic */ androidx.compose.ui.text.input.s g;
    public final /* synthetic */ androidx.compose.ui.unit.b h;
    public final /* synthetic */ int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public A(androidx.compose.foundation.text.selection.i0 i0Var, C0492h0 c0492h0, boolean z, boolean z2, Function1 function1, androidx.compose.ui.text.input.A a, androidx.compose.ui.text.input.s sVar, androidx.compose.ui.unit.b bVar, int i) {
        super(2);
        this.a = i0Var;
        this.b = c0492h0;
        this.c = z;
        this.d = z2;
        this.e = (kotlin.jvm.internal.r) function1;
        this.f = a;
        this.g = sVar;
        this.h = bVar;
        this.i = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00bd  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x001c  */
    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r9, java.lang.Object r10) {
        /*
            r8 = this;
            androidx.compose.runtime.l r9 = (androidx.compose.runtime.InterfaceC0806l) r9
            java.lang.Number r10 = (java.lang.Number) r10
            int r10 = r10.intValue()
            r10 = r10 & 3
            r0 = 2
            if (r10 != r0) goto L1c
            r10 = r9
            androidx.compose.runtime.p r10 = (androidx.compose.runtime.C0814p) r10
            boolean r0 = r10.x()
            if (r0 != 0) goto L17
            goto L1c
        L17:
            r10.Q()
            goto Lc6
        L1c:
            androidx.compose.foundation.text.z r1 = new androidx.compose.foundation.text.z
            androidx.compose.foundation.text.h0 r2 = r8.b
            kotlin.jvm.internal.r r3 = r8.e
            androidx.compose.ui.unit.b r6 = r8.h
            int r7 = r8.i
            androidx.compose.ui.text.input.A r4 = r8.f
            androidx.compose.ui.text.input.s r5 = r8.g
            r1.<init>(r2, r3, r4, r5, r6, r7)
            androidx.compose.ui.n r10 = androidx.compose.ui.n.b
            r0 = r9
            androidx.compose.runtime.p r0 = (androidx.compose.runtime.C0814p) r0
            int r3 = r0.P
            androidx.compose.runtime.j0 r4 = r0.l()
            androidx.compose.ui.q r10 = androidx.compose.ui.a.c(r9, r10)
            androidx.compose.ui.node.j r5 = androidx.compose.ui.node.InterfaceC0915k.D0
            r5.getClass()
            androidx.compose.ui.node.i r5 = androidx.compose.ui.node.C0914j.b
            r0.b0()
            boolean r6 = r0.O
            if (r6 == 0) goto L4e
            r0.k(r5)
            goto L51
        L4e:
            r0.l0()
        L51:
            androidx.compose.ui.node.h r5 = androidx.compose.ui.node.C0914j.f
            androidx.compose.runtime.C0776c.E(r9, r1, r5)
            androidx.compose.ui.node.h r1 = androidx.compose.ui.node.C0914j.e
            androidx.compose.runtime.C0776c.E(r9, r4, r1)
            androidx.compose.ui.node.h r1 = androidx.compose.ui.node.C0914j.g
            boolean r4 = r0.O
            if (r4 != 0) goto L6f
            java.lang.Object r4 = r0.I()
            java.lang.Integer r5 = java.lang.Integer.valueOf(r3)
            boolean r4 = kotlin.jvm.internal.Intrinsics.b(r4, r5)
            if (r4 != 0) goto L72
        L6f:
            android.support.v4.media.session.a.z(r3, r0, r3, r1)
        L72:
            androidx.compose.ui.node.h r1 = androidx.compose.ui.node.C0914j.d
            androidx.compose.runtime.C0776c.E(r9, r10, r1)
            r10 = 1
            r0.p(r10)
            androidx.compose.foundation.text.V r1 = r2.a()
            androidx.compose.foundation.text.V r3 = androidx.compose.foundation.text.V.a
            boolean r4 = r8.c
            r5 = 0
            if (r1 == r3) goto L9c
            androidx.compose.ui.layout.r r1 = r2.c()
            if (r1 == 0) goto L9c
            androidx.compose.ui.layout.r r1 = r2.c()
            kotlin.jvm.internal.Intrinsics.d(r1)
            boolean r1 = r1.k()
            if (r1 == 0) goto L9c
            if (r4 == 0) goto L9c
            goto L9d
        L9c:
            r10 = r5
        L9d:
            androidx.compose.foundation.text.selection.i0 r1 = r8.a
            androidx.compose.foundation.text.AbstractC0484d0.j(r1, r10, r9, r5)
            androidx.compose.foundation.text.V r10 = r2.a()
            androidx.compose.foundation.text.V r2 = androidx.compose.foundation.text.V.c
            if (r10 != r2) goto Lbd
            boolean r10 = r8.d
            if (r10 != 0) goto Lbd
            if (r4 == 0) goto Lbd
            r10 = -2032274(0xffffffffffe0fd6e, float:NaN)
            r0.X(r10)
            androidx.compose.foundation.text.AbstractC0484d0.i(r1, r9, r5)
            r0.p(r5)
            goto Lc6
        Lbd:
            r9 = -1955394(0xffffffffffe229be, float:NaN)
            r0.X(r9)
            r0.p(r5)
        Lc6:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.A.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
