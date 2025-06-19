package androidx.compose.material3;

import androidx.compose.foundation.C0555x;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class Z3 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ androidx.compose.ui.graphics.V b;
    public final /* synthetic */ long c;
    public final /* synthetic */ float d;
    public final /* synthetic */ C0555x e;
    public final /* synthetic */ boolean f;
    public final /* synthetic */ androidx.compose.foundation.interaction.l g;
    public final /* synthetic */ boolean h;
    public final /* synthetic */ Function0 i;
    public final /* synthetic */ float j;
    public final /* synthetic */ androidx.compose.runtime.internal.d k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Z3(androidx.compose.ui.q qVar, androidx.compose.ui.graphics.V v, long j, float f, C0555x c0555x, boolean z, androidx.compose.foundation.interaction.l lVar, boolean z2, Function0 function0, float f2, androidx.compose.runtime.internal.d dVar) {
        super(2);
        this.a = qVar;
        this.b = v;
        this.c = j;
        this.d = f;
        this.e = c0555x;
        this.f = z;
        this.g = lVar;
        this.h = z2;
        this.i = function0;
        this.j = f2;
        this.k = dVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0022  */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r21, java.lang.Object r22) {
        /*
            r20 = this;
            r0 = r20
            r1 = r21
            androidx.compose.runtime.l r1 = (androidx.compose.runtime.InterfaceC0806l) r1
            r2 = r22
            java.lang.Number r2 = (java.lang.Number) r2
            int r2 = r2.intValue()
            r2 = r2 & 3
            r3 = 2
            if (r2 != r3) goto L22
            r2 = r1
            androidx.compose.runtime.p r2 = (androidx.compose.runtime.C0814p) r2
            boolean r3 = r2.x()
            if (r3 != 0) goto L1d
            goto L22
        L1d:
            r2.Q()
            goto Lc3
        L22:
            androidx.compose.runtime.X0 r2 = androidx.compose.material3.F1.a
            androidx.compose.material3.MinimumInteractiveModifier r2 = androidx.compose.material3.MinimumInteractiveModifier.b
            androidx.compose.ui.q r3 = r0.a
            androidx.compose.ui.q r4 = r3.g(r2)
            long r2 = r0.c
            float r5 = r0.d
            long r6 = androidx.compose.material3.AbstractC0594b4.e(r2, r5, r1)
            androidx.compose.runtime.X0 r2 = androidx.compose.ui.platform.AbstractC0955m0.f
            r12 = r1
            androidx.compose.runtime.p r12 = (androidx.compose.runtime.C0814p) r12
            java.lang.Object r1 = r12.j(r2)
            float r2 = r0.j
            androidx.compose.ui.unit.b r1 = (androidx.compose.ui.unit.b) r1
            float r9 = r1.c0(r2)
            androidx.compose.ui.graphics.V r5 = r0.b
            androidx.compose.foundation.x r8 = r0.e
            androidx.compose.ui.q r1 = androidx.compose.material3.AbstractC0594b4.d(r4, r5, r6, r8, r9)
            r13 = 0
            r14 = 7
            r8 = 0
            r9 = 0
            r10 = 0
            androidx.compose.foundation.j0 r16 = androidx.compose.material3.AbstractC0696o3.c(r8, r9, r10, r12, r13, r14)
            androidx.compose.foundation.interaction.l r15 = r0.g
            boolean r2 = r0.h
            boolean r14 = r0.f
            r18 = 0
            kotlin.jvm.functions.Function0 r3 = r0.i
            r13 = r1
            r17 = r2
            r19 = r3
            androidx.compose.ui.q r1 = androidx.compose.foundation.selection.d.a(r13, r14, r15, r16, r17, r18, r19)
            androidx.compose.ui.i r2 = androidx.compose.ui.b.a
            r3 = 1
            androidx.compose.ui.layout.K r2 = androidx.compose.foundation.layout.AbstractC0409s.e(r2, r3)
            int r4 = r12.P
            androidx.compose.runtime.j0 r5 = r12.l()
            androidx.compose.ui.q r1 = androidx.compose.ui.a.c(r12, r1)
            androidx.compose.ui.node.j r6 = androidx.compose.ui.node.InterfaceC0915k.D0
            r6.getClass()
            androidx.compose.ui.node.i r6 = androidx.compose.ui.node.C0914j.b
            r12.b0()
            boolean r7 = r12.O
            if (r7 == 0) goto L8d
            r12.k(r6)
            goto L90
        L8d:
            r12.l0()
        L90:
            androidx.compose.ui.node.h r6 = androidx.compose.ui.node.C0914j.f
            androidx.compose.runtime.C0776c.E(r12, r2, r6)
            androidx.compose.ui.node.h r2 = androidx.compose.ui.node.C0914j.e
            androidx.compose.runtime.C0776c.E(r12, r5, r2)
            androidx.compose.ui.node.h r2 = androidx.compose.ui.node.C0914j.g
            boolean r5 = r12.O
            if (r5 != 0) goto Lae
            java.lang.Object r5 = r12.I()
            java.lang.Integer r6 = java.lang.Integer.valueOf(r4)
            boolean r5 = kotlin.jvm.internal.Intrinsics.b(r5, r6)
            if (r5 != 0) goto Lb1
        Lae:
            android.support.v4.media.session.a.z(r4, r12, r4, r2)
        Lb1:
            androidx.compose.ui.node.h r2 = androidx.compose.ui.node.C0914j.d
            androidx.compose.runtime.C0776c.E(r12, r1, r2)
            r1 = 0
            java.lang.Integer r1 = java.lang.Integer.valueOf(r1)
            androidx.compose.runtime.internal.d r2 = r0.k
            r2.invoke(r12, r1)
            r12.p(r3)
        Lc3:
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.Z3.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
