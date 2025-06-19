package com.quizlet.features.practicetest.results.composables;

/* loaded from: classes3.dex */
public final class g implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;

    public g(int i, int i2, int i3) {
        this.a = i;
        this.b = i2;
        this.c = i3;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0024  */
    @Override // kotlin.jvm.functions.c
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r12, java.lang.Object r13, java.lang.Object r14) {
        /*
            r11 = this;
            androidx.compose.foundation.layout.C r12 = (androidx.compose.foundation.layout.C) r12
            androidx.compose.runtime.l r13 = (androidx.compose.runtime.InterfaceC0806l) r13
            java.lang.Number r14 = (java.lang.Number) r14
            int r14 = r14.intValue()
            java.lang.String r0 = "$this$Card"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r12, r0)
            r12 = r14 & 17
            r14 = 16
            if (r12 != r14) goto L24
            r12 = r13
            androidx.compose.runtime.p r12 = (androidx.compose.runtime.C0814p) r12
            boolean r14 = r12.x()
            if (r14 != 0) goto L1f
            goto L24
        L1f:
            r12.Q()
            goto Ldd
        L24:
            androidx.compose.ui.n r12 = androidx.compose.ui.n.b
            com.quizlet.themes.m r14 = com.quizlet.themes.m.g
            r14.s()
            float r0 = com.quizlet.ui.resources.designsystem.generated.j.h
            androidx.compose.ui.q r0 = androidx.compose.foundation.layout.AbstractC0382e.u(r12, r0)
            androidx.compose.foundation.layout.f r1 = androidx.compose.foundation.layout.AbstractC0398m.c
            androidx.compose.ui.g r2 = androidx.compose.ui.b.m
            r3 = 0
            androidx.compose.foundation.layout.B r1 = androidx.compose.foundation.layout.A.a(r1, r2, r13, r3)
            r2 = r13
            androidx.compose.runtime.p r2 = (androidx.compose.runtime.C0814p) r2
            int r4 = r2.P
            androidx.compose.runtime.j0 r5 = r2.l()
            androidx.compose.ui.q r0 = androidx.compose.ui.a.c(r13, r0)
            androidx.compose.ui.node.j r6 = androidx.compose.ui.node.InterfaceC0915k.D0
            r6.getClass()
            androidx.compose.ui.node.i r6 = androidx.compose.ui.node.C0914j.b
            r2.b0()
            boolean r7 = r2.O
            if (r7 == 0) goto L59
            r2.k(r6)
            goto L5c
        L59:
            r2.l0()
        L5c:
            androidx.compose.ui.node.h r6 = androidx.compose.ui.node.C0914j.f
            androidx.compose.runtime.C0776c.E(r13, r1, r6)
            androidx.compose.ui.node.h r1 = androidx.compose.ui.node.C0914j.e
            androidx.compose.runtime.C0776c.E(r13, r5, r1)
            androidx.compose.ui.node.h r1 = androidx.compose.ui.node.C0914j.g
            boolean r5 = r2.O
            if (r5 != 0) goto L7a
            java.lang.Object r5 = r2.I()
            java.lang.Integer r6 = java.lang.Integer.valueOf(r4)
            boolean r5 = kotlin.jvm.internal.Intrinsics.b(r5, r6)
            if (r5 != 0) goto L7d
        L7a:
            android.support.v4.media.session.a.z(r4, r2, r4, r1)
        L7d:
            androidx.compose.ui.node.h r1 = androidx.compose.ui.node.C0914j.d
            androidx.compose.runtime.C0776c.E(r13, r0, r1)
            r0 = 2132019308(0x7f14086c, float:1.9676947E38)
            java.lang.String r0 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5.d(r13, r0)
            int r1 = r11.a
            java.lang.Integer r1 = java.lang.Integer.valueOf(r1)
            java.lang.Object[] r1 = new java.lang.Object[]{r1}
            r4 = 2132019309(0x7f14086d, float:1.967695E38)
            java.lang.String r1 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5.c(r4, r1, r13)
            java.lang.String r4 = "score"
            androidx.compose.ui.q r5 = androidx.compose.ui.platform.N.G(r12, r4)
            r14.q()
            float r9 = com.quizlet.ui.resources.designsystem.generated.j.i
            r6 = 0
            r10 = 7
            r7 = 0
            r8 = 0
            androidx.compose.ui.q r14 = androidx.compose.foundation.layout.AbstractC0382e.y(r5, r6, r7, r8, r9, r10)
            androidx.transition.C1413p.e(r0, r1, r14, r13, r3)
            r14 = 2132019305(0x7f140869, float:1.9676941E38)
            java.lang.String r14 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5.d(r13, r14)
            int r0 = r11.b
            java.lang.Integer r0 = java.lang.Integer.valueOf(r0)
            int r1 = r11.c
            java.lang.Integer r1 = java.lang.Integer.valueOf(r1)
            java.lang.Object[] r0 = new java.lang.Object[]{r0, r1}
            r1 = 2132019306(0x7f14086a, float:1.9676943E38)
            java.lang.String r0 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5.c(r1, r0, r13)
            java.lang.String r1 = "fraction"
            androidx.compose.ui.q r12 = androidx.compose.ui.platform.N.G(r12, r1)
            r1 = 384(0x180, float:5.38E-43)
            androidx.transition.C1413p.e(r14, r0, r12, r13, r1)
            r12 = 1
            r2.p(r12)
        Ldd:
            kotlin.Unit r12 = kotlin.Unit.a
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.results.composables.g.invoke(java.lang.Object, java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
