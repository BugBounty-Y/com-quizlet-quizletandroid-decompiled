package androidx.compose.foundation.text.selection;

import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class e0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ androidx.compose.runtime.internal.d c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e0(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar) {
        super(2);
        this.a = 1;
        this.b = qVar;
        this.c = dVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x003a  */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r10, java.lang.Object r11) {
        /*
            r9 = this;
            r0 = 2
            androidx.compose.ui.q r1 = r9.b
            androidx.compose.runtime.internal.d r2 = r9.c
            int r3 = r9.a
            switch(r3) {
                case 0: goto Lcd;
                case 1: goto L1f;
                default: goto La;
            }
        La:
            androidx.compose.runtime.l r10 = (androidx.compose.runtime.InterfaceC0806l) r10
            java.lang.Number r11 = (java.lang.Number) r11
            r11.intValue()
            r11 = 391(0x187, float:5.48E-43)
            int r11 = androidx.compose.runtime.C0776c.H(r11)
            androidx.compose.runtime.internal.d r0 = com.quizlet.assembly.compose.pills.k.a
            androidx.compose.material3.H.b(r1, r2, r10, r11)
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        L1f:
            androidx.compose.runtime.l r10 = (androidx.compose.runtime.InterfaceC0806l) r10
            java.lang.Number r11 = (java.lang.Number) r11
            int r11 = r11.intValue()
            r11 = r11 & 3
            if (r11 != r0) goto L3a
            r11 = r10
            androidx.compose.runtime.p r11 = (androidx.compose.runtime.C0814p) r11
            boolean r1 = r11.x()
            if (r1 != 0) goto L35
            goto L3a
        L35:
            r11.Q()
            goto Lca
        L3a:
            r11 = 2132018733(0x7f14062d, float:1.967578E38)
            java.lang.String r11 = androidx.compose.material3.internal.AbstractC0646j.g(r10, r11)
            float r4 = androidx.compose.material3.AbstractC0625h.a
            float r6 = androidx.compose.material3.AbstractC0625h.b
            androidx.compose.ui.q r3 = r9.b
            r8 = 10
            r5 = 0
            r7 = 0
            androidx.compose.ui.q r1 = androidx.compose.foundation.layout.K0.n(r3, r4, r5, r6, r7, r8)
            androidx.compose.ui.n r3 = androidx.compose.ui.n.b
            androidx.compose.runtime.p r10 = (androidx.compose.runtime.C0814p) r10
            boolean r4 = r10.f(r11)
            java.lang.Object r5 = r10.I()
            if (r4 != 0) goto L61
            androidx.compose.runtime.V r4 = androidx.compose.runtime.C0804k.a
            if (r5 != r4) goto L69
        L61:
            androidx.compose.foundation.i0 r5 = new androidx.compose.foundation.i0
            r5.<init>(r11, r0)
            r10.i0(r5)
        L69:
            kotlin.jvm.functions.Function1 r5 = (kotlin.jvm.functions.Function1) r5
            r11 = 0
            androidx.compose.ui.q r0 = androidx.compose.ui.semantics.m.a(r3, r11, r5)
            androidx.compose.ui.q r0 = r1.g(r0)
            androidx.compose.ui.i r1 = androidx.compose.ui.b.a
            r3 = 1
            androidx.compose.ui.layout.K r1 = androidx.compose.foundation.layout.AbstractC0409s.e(r1, r3)
            int r4 = r10.P
            androidx.compose.runtime.j0 r5 = r10.l()
            androidx.compose.ui.q r0 = androidx.compose.ui.a.c(r10, r0)
            androidx.compose.ui.node.j r6 = androidx.compose.ui.node.InterfaceC0915k.D0
            r6.getClass()
            androidx.compose.ui.node.i r6 = androidx.compose.ui.node.C0914j.b
            r10.b0()
            boolean r7 = r10.O
            if (r7 == 0) goto L97
            r10.k(r6)
            goto L9a
        L97:
            r10.l0()
        L9a:
            androidx.compose.ui.node.h r6 = androidx.compose.ui.node.C0914j.f
            androidx.compose.runtime.C0776c.E(r10, r1, r6)
            androidx.compose.ui.node.h r1 = androidx.compose.ui.node.C0914j.e
            androidx.compose.runtime.C0776c.E(r10, r5, r1)
            androidx.compose.ui.node.h r1 = androidx.compose.ui.node.C0914j.g
            boolean r5 = r10.O
            if (r5 != 0) goto Lb8
            java.lang.Object r5 = r10.I()
            java.lang.Integer r6 = java.lang.Integer.valueOf(r4)
            boolean r5 = kotlin.jvm.internal.Intrinsics.b(r5, r6)
            if (r5 != 0) goto Lbb
        Lb8:
            android.support.v4.media.session.a.z(r4, r10, r4, r1)
        Lbb:
            androidx.compose.ui.node.h r1 = androidx.compose.ui.node.C0914j.d
            androidx.compose.runtime.C0776c.E(r10, r0, r1)
            java.lang.Integer r11 = java.lang.Integer.valueOf(r11)
            r2.invoke(r10, r11)
            r10.p(r3)
        Lca:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        Lcd:
            androidx.compose.runtime.l r10 = (androidx.compose.runtime.InterfaceC0806l) r10
            java.lang.Number r11 = (java.lang.Number) r11
            r11.intValue()
            r11 = 49
            int r11 = androidx.compose.runtime.C0776c.H(r11)
            androidx.compose.foundation.text.selection.W.f(r1, r2, r10, r11)
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.e0.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e0(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        super(2);
        this.a = i2;
        switch (i2) {
            case 2:
                androidx.compose.runtime.internal.d dVar2 = com.quizlet.assembly.compose.pills.k.a;
                this.b = qVar;
                this.c = dVar;
                super(2);
                break;
            default:
                this.b = qVar;
                this.c = dVar;
                break;
        }
    }
}
