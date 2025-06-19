package com.quizlet.features.achievements.ui.composables;

import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public final class H implements kotlin.jvm.functions.c {
    public final /* synthetic */ kotlinx.collections.immutable.b a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ InterfaceC0773a0 d;
    public final /* synthetic */ float e;
    public final /* synthetic */ Function1 f;

    public H(float f, int i, int i2, InterfaceC0773a0 interfaceC0773a0, Function1 function1, kotlinx.collections.immutable.b bVar) {
        this.a = bVar;
        this.b = i;
        this.c = i2;
        this.d = interfaceC0773a0;
        this.e = f;
        this.f = function1;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0024  */
    @Override // kotlin.jvm.functions.c
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r11, java.lang.Object r12, java.lang.Object r13) {
        /*
            r10 = this;
            androidx.compose.foundation.layout.l0 r11 = (androidx.compose.foundation.layout.InterfaceC0397l0) r11
            androidx.compose.runtime.l r12 = (androidx.compose.runtime.InterfaceC0806l) r12
            java.lang.Number r13 = (java.lang.Number) r13
            int r13 = r13.intValue()
            java.lang.String r0 = "$this$FlowRow"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r11, r0)
            r11 = r13 & 17
            r13 = 16
            if (r11 != r13) goto L24
            r11 = r12
            androidx.compose.runtime.p r11 = (androidx.compose.runtime.C0814p) r11
            boolean r13 = r11.x()
            if (r13 != 0) goto L1f
            goto L24
        L1f:
            r11.Q()
            goto Lf4
        L24:
            r11 = 2132017200(0x7f140030, float:1.9672672E38)
            java.lang.String r11 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5.d(r12, r11)
            androidx.compose.ui.n r13 = androidx.compose.ui.n.b
            r0 = 1065353216(0x3f800000, float:1.0)
            androidx.compose.ui.q r1 = androidx.compose.foundation.layout.K0.c(r13, r0)
            r2 = 48
            r3 = 0
            com.facebook.appevents.codeless.i.a(r2, r3, r12, r1, r11)
            androidx.compose.runtime.p r12 = (androidx.compose.runtime.C0814p) r12
            r11 = -229750631(0xfffffffff24e4899, float:-4.0858673E30)
            r12.X(r11)
            androidx.compose.runtime.a0 r11 = r10.d
            java.lang.Object r1 = r11.getValue()
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r1 = r1.booleanValue()
            kotlinx.collections.immutable.b r2 = r10.a
            if (r1 == 0) goto L56
            int r1 = r2.size()
            goto L58
        L56:
            int r1 = r10.b
        L58:
            java.util.List r1 = kotlin.collections.CollectionsKt.p0(r2, r1)
            java.util.Iterator r1 = r1.iterator()
        L60:
            boolean r4 = r1.hasNext()
            androidx.compose.runtime.V r5 = androidx.compose.runtime.C0804k.a
            float r6 = r10.e
            if (r4 == 0) goto L9f
            java.lang.Object r4 = r1.next()
            com.quizlet.data.model.c r4 = (com.quizlet.data.model.C4114c) r4
            androidx.compose.ui.q r6 = androidx.compose.foundation.layout.K0.o(r13, r6)
            r7 = 971411858(0x39e69192, float:4.3977477E-4)
            r12.X(r7)
            kotlin.jvm.functions.Function1 r7 = r10.f
            boolean r8 = r12.f(r7)
            boolean r9 = r12.h(r4)
            r8 = r8 | r9
            java.lang.Object r9 = r12.I()
            if (r8 != 0) goto L8d
            if (r9 != r5) goto L96
        L8d:
            com.quizlet.features.achievements.ui.composables.q r9 = new com.quizlet.features.achievements.ui.composables.q
            r5 = 6
            r9.<init>(r7, r4, r5)
            r12.i0(r9)
        L96:
            kotlin.jvm.functions.Function0 r9 = (kotlin.jvm.functions.Function0) r9
            r12.p(r3)
            com.facebook.appevents.g.a(r4, r6, r9, r12, r3)
            goto L60
        L9f:
            r12.p(r3)
            r1 = -229737102(0xfffffffff24e7d72, float:-4.0899562E30)
            r12.X(r1)
            int r1 = r2.size()
            int r2 = r10.c
            int r1 = r1 % r2
            int r2 = r2 - r1
            r1 = r3
        Lb1:
            if (r1 >= r2) goto Lbd
            androidx.compose.ui.q r4 = androidx.compose.foundation.layout.K0.o(r13, r6)
            androidx.compose.foundation.layout.AbstractC0382e.f(r12, r4)
            int r1 = r1 + 1
            goto Lb1
        Lbd:
            r12.p(r3)
            java.lang.Object r1 = r11.getValue()
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r1 = r1.booleanValue()
            r2 = -229730053(0xfffffffff24e98fb, float:-4.0920867E30)
            r12.X(r2)
            boolean r2 = r12.f(r11)
            java.lang.Object r4 = r12.I()
            if (r2 != 0) goto Ldc
            if (r4 != r5) goto Le6
        Ldc:
            androidx.navigation.compose.z r4 = new androidx.navigation.compose.z
            r2 = 10
            r4.<init>(r11, r2)
            r12.i0(r4)
        Le6:
            kotlin.jvm.functions.Function0 r4 = (kotlin.jvm.functions.Function0) r4
            r12.p(r3)
            androidx.compose.ui.q r11 = androidx.compose.foundation.layout.K0.c(r13, r0)
            r13 = 384(0x180, float:5.38E-43)
            com.facebook.appevents.i.a(r13, r12, r11, r4, r1)
        Lf4:
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.achievements.ui.composables.H.invoke(java.lang.Object, java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
