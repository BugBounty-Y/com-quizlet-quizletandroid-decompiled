package com.quizlet.ui.compose;

import androidx.compose.foundation.layout.A0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class Z implements Function2 {
    public final /* synthetic */ float a;
    public final /* synthetic */ A0 b;
    public final /* synthetic */ androidx.compose.runtime.internal.d c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ long e;

    public Z(float f, A0 a0, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, long j) {
        this.a = f;
        this.b = a0;
        this.c = dVar;
        this.d = dVar2;
        this.e = j;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x001c  */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r14, java.lang.Object r15) {
        /*
            r13 = this;
            androidx.compose.runtime.l r14 = (androidx.compose.runtime.InterfaceC0806l) r14
            java.lang.Number r15 = (java.lang.Number) r15
            int r15 = r15.intValue()
            r15 = r15 & 3
            r0 = 2
            if (r15 != r0) goto L1c
            r15 = r14
            androidx.compose.runtime.p r15 = (androidx.compose.runtime.C0814p) r15
            boolean r0 = r15.x()
            if (r0 != 0) goto L17
            goto L1c
        L17:
            r15.Q()
            goto Lfb
        L1c:
            androidx.compose.ui.n r15 = androidx.compose.ui.n.b
            r0 = 0
            float r1 = r13.a
            r2 = 1
            androidx.compose.ui.q r0 = androidx.compose.foundation.layout.K0.b(r15, r0, r1, r2)
            androidx.compose.foundation.layout.A0 r1 = r13.b
            androidx.compose.ui.q r0 = androidx.compose.foundation.layout.AbstractC0382e.t(r0, r1)
            androidx.compose.foundation.layout.d r1 = androidx.compose.foundation.layout.AbstractC0398m.a
            float r1 = com.quizlet.ui.compose.c0.a
            androidx.compose.foundation.layout.j r1 = androidx.compose.foundation.layout.AbstractC0398m.g(r1)
            androidx.compose.ui.h r3 = androidx.compose.ui.b.k
            r4 = 54
            androidx.compose.foundation.layout.G0 r1 = androidx.compose.foundation.layout.E0.b(r1, r3, r14, r4)
            r3 = r14
            androidx.compose.runtime.p r3 = (androidx.compose.runtime.C0814p) r3
            int r4 = r3.P
            androidx.compose.runtime.j0 r5 = r3.l()
            androidx.compose.ui.q r0 = androidx.compose.ui.a.c(r14, r0)
            androidx.compose.ui.node.j r6 = androidx.compose.ui.node.InterfaceC0915k.D0
            r6.getClass()
            androidx.compose.ui.node.i r6 = androidx.compose.ui.node.C0914j.b
            r3.b0()
            boolean r7 = r3.O
            if (r7 == 0) goto L5b
            r3.k(r6)
            goto L5e
        L5b:
            r3.l0()
        L5e:
            androidx.compose.ui.node.h r7 = androidx.compose.ui.node.C0914j.f
            androidx.compose.runtime.C0776c.E(r14, r1, r7)
            androidx.compose.ui.node.h r1 = androidx.compose.ui.node.C0914j.e
            androidx.compose.runtime.C0776c.E(r14, r5, r1)
            androidx.compose.ui.node.h r5 = androidx.compose.ui.node.C0914j.g
            boolean r8 = r3.O
            if (r8 != 0) goto L7c
            java.lang.Object r8 = r3.I()
            java.lang.Integer r9 = java.lang.Integer.valueOf(r4)
            boolean r8 = kotlin.jvm.internal.Intrinsics.b(r8, r9)
            if (r8 != 0) goto L7f
        L7c:
            android.support.v4.media.session.a.z(r4, r3, r4, r5)
        L7f:
            androidx.compose.ui.node.h r4 = androidx.compose.ui.node.C0914j.d
            androidx.compose.runtime.C0776c.E(r14, r0, r4)
            r0 = -1994509142(0xffffffff891e34aa, float:-1.904332E-33)
            r3.X(r0)
            r0 = 0
            androidx.compose.runtime.internal.d r8 = r13.c
            if (r8 == 0) goto Le0
            androidx.compose.ui.i r9 = androidx.compose.ui.b.e
            androidx.compose.ui.layout.K r9 = androidx.compose.foundation.layout.AbstractC0409s.e(r9, r0)
            int r10 = r3.P
            androidx.compose.runtime.j0 r11 = r3.l()
            androidx.compose.ui.q r15 = androidx.compose.ui.a.c(r14, r15)
            r3.b0()
            boolean r12 = r3.O
            if (r12 == 0) goto Laa
            r3.k(r6)
            goto Lad
        Laa:
            r3.l0()
        Lad:
            androidx.compose.runtime.C0776c.E(r14, r9, r7)
            androidx.compose.runtime.C0776c.E(r14, r11, r1)
            boolean r1 = r3.O
            if (r1 != 0) goto Lc5
            java.lang.Object r1 = r3.I()
            java.lang.Integer r6 = java.lang.Integer.valueOf(r10)
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r1, r6)
            if (r1 != 0) goto Lc8
        Lc5:
            android.support.v4.media.session.a.z(r10, r3, r10, r5)
        Lc8:
            androidx.compose.runtime.C0776c.E(r14, r15, r4)
            androidx.compose.runtime.B r15 = androidx.compose.material3.AbstractC0669k0.a
            androidx.compose.ui.graphics.v r1 = new androidx.compose.ui.graphics.v
            long r4 = r13.e
            r1.<init>(r4)
            androidx.compose.runtime.n0 r15 = r15.a(r1)
            r1 = 8
            androidx.compose.runtime.C0776c.a(r15, r8, r14, r1)
            r3.p(r2)
        Le0:
            r3.p(r0)
            r15 = -1994499162(0xffffffff891e5ba6, float:-1.9061651E-33)
            r3.X(r15)
            androidx.compose.runtime.internal.d r15 = r13.d
            if (r15 != 0) goto Lee
            goto Lf5
        Lee:
            java.lang.Integer r1 = java.lang.Integer.valueOf(r0)
            r15.invoke(r14, r1)
        Lf5:
            r3.p(r0)
            r3.p(r2)
        Lfb:
            kotlin.Unit r14 = kotlin.Unit.a
            return r14
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.ui.compose.Z.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
