package androidx.compose.foundation.text.selection;

import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.selection.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0521b extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ long a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ InterfaceC0533n d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0521b(long j, boolean z, androidx.compose.ui.q qVar, InterfaceC0533n interfaceC0533n) {
        super(2);
        this.a = j;
        this.b = z;
        this.c = qVar;
        this.d = interfaceC0533n;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x001c  */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r13, java.lang.Object r14) {
        /*
            r12 = this;
            androidx.compose.runtime.l r13 = (androidx.compose.runtime.InterfaceC0806l) r13
            java.lang.Number r14 = (java.lang.Number) r14
            int r14 = r14.intValue()
            r14 = r14 & 3
            r0 = 2
            if (r14 != r0) goto L1c
            r14 = r13
            androidx.compose.runtime.p r14 = (androidx.compose.runtime.C0814p) r14
            boolean r0 = r14.x()
            if (r0 != 0) goto L17
            goto L1c
        L17:
            r14.Q()
            goto Le6
        L1c:
            r0 = 9205357640488583168(0x7fc000007fc00000, double:2.247117487993712E307)
            long r2 = r12.a
            int r14 = (r2 > r0 ? 1 : (r2 == r0 ? 0 : -1))
            androidx.compose.runtime.V r0 = androidx.compose.runtime.C0804k.a
            androidx.compose.foundation.text.selection.n r1 = r12.d
            boolean r4 = r12.b
            r5 = 0
            if (r14 == 0) goto Lbf
            androidx.compose.runtime.p r13 = (androidx.compose.runtime.C0814p) r13
            r14 = -837727128(0xffffffffce114c68, float:-6.094259E8)
            r13.X(r14)
            if (r4 == 0) goto L3b
            androidx.compose.foundation.layout.d r14 = androidx.compose.foundation.layout.AbstractC0382e.b
            goto L3d
        L3b:
            androidx.compose.foundation.layout.d r14 = androidx.compose.foundation.layout.AbstractC0382e.a
        L3d:
            float r7 = androidx.compose.ui.unit.g.b(r2)
            float r8 = androidx.compose.ui.unit.g.a(r2)
            androidx.compose.ui.q r6 = r12.c
            r11 = 12
            r9 = 0
            r10 = 0
            androidx.compose.ui.q r2 = androidx.compose.foundation.layout.K0.j(r6, r7, r8, r9, r10, r11)
            androidx.compose.ui.h r3 = androidx.compose.ui.b.j
            androidx.compose.foundation.layout.G0 r14 = androidx.compose.foundation.layout.E0.b(r14, r3, r13, r5)
            int r3 = r13.P
            androidx.compose.runtime.j0 r6 = r13.l()
            androidx.compose.ui.q r2 = androidx.compose.ui.a.c(r13, r2)
            androidx.compose.ui.node.j r7 = androidx.compose.ui.node.InterfaceC0915k.D0
            r7.getClass()
            androidx.compose.ui.node.i r7 = androidx.compose.ui.node.C0914j.b
            r13.b0()
            boolean r8 = r13.O
            if (r8 == 0) goto L71
            r13.k(r7)
            goto L74
        L71:
            r13.l0()
        L74:
            androidx.compose.ui.node.h r7 = androidx.compose.ui.node.C0914j.f
            androidx.compose.runtime.C0776c.E(r13, r14, r7)
            androidx.compose.ui.node.h r14 = androidx.compose.ui.node.C0914j.e
            androidx.compose.runtime.C0776c.E(r13, r6, r14)
            androidx.compose.ui.node.h r14 = androidx.compose.ui.node.C0914j.g
            boolean r6 = r13.O
            if (r6 != 0) goto L92
            java.lang.Object r6 = r13.I()
            java.lang.Integer r7 = java.lang.Integer.valueOf(r3)
            boolean r6 = kotlin.jvm.internal.Intrinsics.b(r6, r7)
            if (r6 != 0) goto L95
        L92:
            android.support.v4.media.session.a.z(r3, r13, r3, r14)
        L95:
            androidx.compose.ui.node.h r14 = androidx.compose.ui.node.C0914j.d
            androidx.compose.runtime.C0776c.E(r13, r2, r14)
            androidx.compose.ui.n r14 = androidx.compose.ui.n.b
            boolean r2 = r13.h(r1)
            java.lang.Object r3 = r13.I()
            if (r2 != 0) goto La8
            if (r3 != r0) goto Lb1
        La8:
            androidx.compose.foundation.text.selection.a r3 = new androidx.compose.foundation.text.selection.a
            r0 = 0
            r3.<init>(r1, r0)
            r13.i0(r3)
        Lb1:
            kotlin.jvm.functions.Function0 r3 = (kotlin.jvm.functions.Function0) r3
            r0 = 6
            androidx.compose.foundation.text.selection.W.e(r0, r13, r14, r3, r4)
            r14 = 1
            r13.p(r14)
            r13.p(r5)
            goto Le6
        Lbf:
            androidx.compose.runtime.p r13 = (androidx.compose.runtime.C0814p) r13
            r14 = -836867312(0xffffffffce1e6b10, float:-6.6445414E8)
            r13.X(r14)
            boolean r14 = r13.h(r1)
            java.lang.Object r2 = r13.I()
            if (r14 != 0) goto Ld3
            if (r2 != r0) goto Ldc
        Ld3:
            androidx.compose.foundation.text.selection.a r2 = new androidx.compose.foundation.text.selection.a
            r14 = 1
            r2.<init>(r1, r14)
            r13.i0(r2)
        Ldc:
            kotlin.jvm.functions.Function0 r2 = (kotlin.jvm.functions.Function0) r2
            androidx.compose.ui.q r14 = r12.c
            androidx.compose.foundation.text.selection.W.e(r5, r13, r14, r2, r4)
            r13.p(r5)
        Le6:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.C0521b.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
