package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.text.C0488f0;
import androidx.compose.foundation.text.C0490g0;
import androidx.compose.material3.A4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3232p5;
import com.quizlet.ui.compose.C4818k;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.p5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3232p5 {
    public static final /* synthetic */ int a = 0;

    public static final void a(final androidx.compose.ui.text.input.A value, final Function1 onValueChange, final androidx.compose.ui.q qVar, final Function1 function1, float f, androidx.compose.material3.A4 a4, boolean z, boolean z2, androidx.compose.ui.text.L l, final C0490g0 c0490g0, final C0488f0 c0488f0, InterfaceC0806l interfaceC0806l, final int i) {
        boolean z3;
        androidx.compose.material3.A4 a4C;
        C0814p c0814p;
        androidx.compose.ui.text.L l2;
        boolean z4;
        boolean z5;
        final boolean z6;
        final boolean z7;
        final float f2;
        final androidx.compose.ui.text.L l3;
        final androidx.compose.material3.A4 a42;
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(onValueChange, "onValueChange");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1046936466);
        int i2 = i | (c0814p2.f(value) ? 4 : 2) | (c0814p2.h(onValueChange) ? 32 : 16) | (c0814p2.f(qVar) ? 256 : 128) | (c0814p2.h(function1) ? 2048 : 1024) | 47783936 | (c0814p2.f(c0490g0) ? 536870912 : 268435456);
        char c = c0814p2.f(c0488f0) ? (char) 4 : (char) 2;
        if ((i2 & 306783379) == 306783378 && (c & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            f2 = f;
            a42 = a4;
            z6 = z;
            z7 = z2;
            l3 = l;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            int i3 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i3 == 0 || c0814p2.w()) {
                com.quizlet.themes.m.g.d();
                float f3 = com.quizlet.ui.resources.designsystem.generated.f.g;
                c0814p2.X(-1900675745);
                androidx.compose.material3.D4 d4 = androidx.compose.material3.D4.a;
                long j = AbstractC3169i5.f(c0814p2).f;
                long j2 = AbstractC3169i5.f(c0814p2).f;
                long j3 = AbstractC3169i5.f(c0814p2).f;
                long j4 = AbstractC3169i5.f(c0814p2).f;
                long j5 = C0861v.f;
                f = f3;
                z3 = false;
                a4C = androidx.compose.material3.D4.c(AbstractC3169i5.f(c0814p2).b.e(), AbstractC3169i5.f(c0814p2).b.f(), AbstractC3169i5.f(c0814p2).b.f(), 0L, j, j2, j3, j4, AbstractC3169i5.f(c0814p2).b.e(), 0L, new androidx.compose.foundation.text.selection.p0(AbstractC3169i5.f(c0814p2).K(), AbstractC3169i5.f(c0814p2).b.c()), j5, j5, 0L, 0L, 0L, 0L, 0L, 0L, 0L, AbstractC3169i5.f(c0814p2).b.f(), 0L, 0L, 0L, 0L, 0L, c0814p2, 2130698760);
                c0814p = c0814p2;
                c0814p.p(false);
                l2 = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).h;
                z4 = true;
                z5 = true;
            } else {
                c0814p2.Q();
                z4 = z;
                z5 = z2;
                l2 = l;
                c0814p = c0814p2;
                z3 = false;
                a4C = a4;
            }
            float f4 = f;
            c0814p.q();
            c0814p.X(-1571979260);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = androidx.compose.animation.d0.i(c0814p);
            }
            androidx.compose.foundation.interaction.l lVar = (androidx.compose.foundation.interaction.l) objI;
            c0814p.p(z3);
            c0814p.X(-1571976454);
            long jC = l2.c();
            if (jC == 16) {
                boolean zBooleanValue = ((Boolean) AbstractC3119d0.h(lVar, c0814p, 6).getValue()).booleanValue();
                Intrinsics.checkNotNullParameter(a4C, "<this>");
                c0814p.X(-409374996);
                jC = !z4 ? a4C.c : zBooleanValue ? a4C.a : a4C.b;
                c0814p.p(z3);
            }
            long j6 = jC;
            c0814p.p(z3);
            androidx.compose.material3.A4 a43 = a4C;
            C0776c.a(androidx.compose.foundation.text.selection.q0.a.a(a4C.k), androidx.compose.runtime.internal.e.e(735547090, new C4818k(qVar, function1, a43, value, onValueChange, z4, l2.e(new androidx.compose.ui.text.L(j6, 0L, null, null, null, 0L, 0, 0L, 16777214)), c0490g0, c0488f0, z5, lVar, f4), c0814p), c0814p, 56);
            z6 = z4;
            z7 = z5;
            f2 = f4;
            l3 = l2;
            a42 = a43;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(onValueChange, qVar, function1, f2, a42, z6, z7, l3, c0490g0, c0488f0, i) { // from class: com.quizlet.ui.compose.i
                public final /* synthetic */ Function1 b;
                public final /* synthetic */ androidx.compose.ui.q c;
                public final /* synthetic */ Function1 d;
                public final /* synthetic */ float e;
                public final /* synthetic */ A4 f;
                public final /* synthetic */ boolean g;
                public final /* synthetic */ boolean h;
                public final /* synthetic */ androidx.compose.ui.text.L i;
                public final /* synthetic */ C0490g0 j;
                public final /* synthetic */ C0488f0 k;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    C0490g0 c0490g02 = this.j;
                    C0488f0 c0488f02 = this.k;
                    AbstractC3232p5.a(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, c0490g02, c0488f02, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static boolean b(int i) {
        int type = Character.getType(i);
        return type == 23 || type == 20 || type == 22 || type == 30 || type == 29 || type == 24 || type == 21;
    }
}
