package com.quizlet.ui.compose;

import androidx.compose.foundation.C0555x;
import androidx.compose.foundation.layout.A0;
import androidx.compose.material3.AbstractC0669k0;
import androidx.compose.material3.F1;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0811n0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class c0 {
    public static final float a = 8;

    public static final void a(final Function0 onClick, final boolean z, final androidx.compose.runtime.internal.d icon, final C4832z colors, final androidx.compose.foundation.shape.d shape, final C0555x c0555x, final float f, final A0 paddingValues, final androidx.compose.foundation.interaction.l lVar, final androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, final int i, final int i2) {
        int i3;
        boolean z2;
        C0555x c0555x2;
        float f2;
        androidx.compose.foundation.interaction.l lVar2;
        androidx.compose.ui.q qVar2;
        int i4;
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        Intrinsics.checkNotNullParameter(icon, "icon");
        Intrinsics.checkNotNullParameter(colors, "colors");
        Intrinsics.checkNotNullParameter(shape, "shape");
        Intrinsics.checkNotNullParameter(paddingValues, "paddingValues");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(362065583);
        if ((i & 6) == 0) {
            i3 = (c0814p.g(false) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.h(onClick) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            z2 = z;
            i3 |= c0814p.g(z2) ? 256 : 128;
        } else {
            z2 = z;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p.h(icon) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p.f(colors) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p.f(shape) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            c0555x2 = c0555x;
            i3 |= c0814p.f(c0555x2) ? 1048576 : 524288;
        } else {
            c0555x2 = c0555x;
        }
        if ((12582912 & i) == 0) {
            f2 = f;
            i3 |= c0814p.c(f2) ? 8388608 : 4194304;
        } else {
            f2 = f;
        }
        if ((100663296 & i) == 0) {
            i3 |= c0814p.f(paddingValues) ? 67108864 : 33554432;
        }
        if ((805306368 & i) == 0) {
            lVar2 = lVar;
            i3 |= c0814p.f(lVar2) ? 536870912 : 268435456;
        } else {
            lVar2 = lVar;
        }
        if ((i2 & 6) == 0) {
            qVar2 = qVar;
            i4 = i2 | (c0814p.f(qVar2) ? 4 : 2);
        } else {
            qVar2 = qVar;
            i4 = i2;
        }
        if ((i3 & 306783379) == 306783378 && (i4 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i5 = i3 << 6;
            c(false, onClick, z2, null, androidx.compose.ui.text.L.d, icon, colors, shape, c0555x2, f2, paddingValues, lVar2, qVar2, c0814p, (i3 & 14) | 27648 | (i3 & ContentType.LONG_FORM_ON_DEMAND) | (i3 & 896) | (i5 & 458752) | (i5 & 3670016) | (i5 & 29360128) | (i5 & 234881024) | (i5 & 1879048192), ((i3 >> 24) & 126) | ((i4 << 6) & 896));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.ui.compose.W
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    int iH2 = C0776c.H(i2);
                    androidx.compose.runtime.internal.d dVar = icon;
                    C4832z c4832z = colors;
                    androidx.compose.foundation.shape.d dVar2 = shape;
                    androidx.compose.foundation.interaction.l lVar3 = lVar;
                    androidx.compose.ui.q qVar3 = qVar;
                    c0.a(onClick, z, dVar, c4832z, dVar2, c0555x, f, paddingValues, lVar3, qVar3, (InterfaceC0806l) obj, iH, iH2);
                    return Unit.a;
                }
            };
        }
    }

    public static final void b(boolean z, Function0 onClick, boolean z2, androidx.compose.runtime.internal.d label, androidx.compose.ui.text.L labelTextStyle, androidx.compose.runtime.internal.d dVar, C4832z colors, androidx.compose.foundation.shape.d shape, C0555x c0555x, float f, A0 paddingValues, androidx.compose.foundation.interaction.l lVar, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        boolean z3;
        int i3;
        boolean z4;
        androidx.compose.runtime.internal.d dVar2;
        int i4;
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        Intrinsics.checkNotNullParameter(label, "label");
        Intrinsics.checkNotNullParameter(labelTextStyle, "labelTextStyle");
        Intrinsics.checkNotNullParameter(colors, "colors");
        Intrinsics.checkNotNullParameter(shape, "shape");
        Intrinsics.checkNotNullParameter(paddingValues, "paddingValues");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-30570977);
        if ((i & 6) == 0) {
            z3 = z;
            i3 = (c0814p.g(z3) ? 4 : 2) | i;
        } else {
            z3 = z;
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.h(onClick) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            z4 = z2;
            i3 |= c0814p.g(z4) ? 256 : 128;
        } else {
            z4 = z2;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p.h(label) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p.f(labelTextStyle) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            dVar2 = dVar;
            i3 |= c0814p.h(dVar2) ? 131072 : 65536;
        } else {
            dVar2 = dVar;
        }
        if ((i & 1572864) == 0) {
            i3 |= c0814p.f(colors) ? 1048576 : 524288;
        }
        if ((i & 12582912) == 0) {
            i3 |= c0814p.f(shape) ? 8388608 : 4194304;
        }
        if ((i & 100663296) == 0) {
            i3 |= c0814p.f(c0555x) ? 67108864 : 33554432;
        }
        if ((i & 805306368) == 0) {
            i3 |= c0814p.c(f) ? 536870912 : 268435456;
        }
        if ((i2 & 6) == 0) {
            i4 = i2 | (c0814p.f(paddingValues) ? 4 : 2);
        } else {
            i4 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 |= c0814p.f(lVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i4 |= c0814p.f(qVar) ? 256 : 128;
        }
        int i5 = i4;
        if ((i3 & 306783379) == 306783378 && (i5 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i6 = i5 & 1022;
            c(z3, onClick, z4, label, labelTextStyle, dVar2, colors, shape, c0555x, f, paddingValues, lVar, qVar, c0814p, 2147483646 & i3, i6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new U(z, onClick, z2, label, labelTextStyle, dVar, colors, shape, c0555x, f, paddingValues, lVar, qVar, i, i2, 1);
        }
    }

    public static final void c(boolean z, Function0 function0, boolean z2, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.text.L l, androidx.compose.runtime.internal.d dVar2, C4832z c4832z, androidx.compose.foundation.shape.d dVar3, C0555x c0555x, float f, A0 a0, androidx.compose.foundation.interaction.l lVar, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        Function0 function02;
        boolean z3;
        androidx.compose.runtime.internal.d dVar4;
        androidx.compose.ui.text.L l2;
        int i4;
        androidx.compose.foundation.interaction.l lVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1131215428);
        if ((i & 6) == 0) {
            i3 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            function02 = function0;
            i3 |= c0814p.h(function02) ? 32 : 16;
        } else {
            function02 = function0;
        }
        if ((i & 384) == 0) {
            z3 = z2;
            i3 |= c0814p.g(z3) ? 256 : 128;
        } else {
            z3 = z2;
        }
        if ((i & 3072) == 0) {
            dVar4 = dVar;
            i3 |= c0814p.h(dVar4) ? 2048 : 1024;
        } else {
            dVar4 = dVar;
        }
        if ((i & 24576) == 0) {
            l2 = l;
            i3 |= c0814p.f(l2) ? 16384 : 8192;
        } else {
            l2 = l;
        }
        if ((i & 196608) == 0) {
            i3 |= c0814p.h(dVar2) ? 131072 : 65536;
        }
        if ((i & 1572864) == 0) {
            i3 |= c0814p.f(c4832z) ? 1048576 : 524288;
        }
        if ((i & 12582912) == 0) {
            i3 |= c0814p.f(dVar3) ? 8388608 : 4194304;
        }
        if ((i & 100663296) == 0) {
            i3 |= c0814p.f(c0555x) ? 67108864 : 33554432;
        }
        if ((i & 805306368) == 0) {
            i3 |= c0814p.c(f) ? 536870912 : 268435456;
        }
        if ((i2 & 6) == 0) {
            i4 = i2 | (c0814p.f(a0) ? 4 : 2);
        } else {
            i4 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 |= c0814p.f(lVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i4 |= c0814p.f(qVar) ? 256 : 128;
        }
        int i5 = i4;
        if ((i3 & 306783379) == 306783378 && (i5 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(-24015972);
            if (lVar == null) {
                c0814p.X(-24015321);
                Object objI = c0814p.I();
                if (objI == C0804k.a) {
                    objI = androidx.compose.animation.d0.i(c0814p);
                }
                c0814p.p(false);
                lVar2 = (androidx.compose.foundation.interaction.l) objI;
            } else {
                lVar2 = lVar;
            }
            c0814p.p(false);
            C0776c.a(F1.a.a(new androidx.compose.ui.unit.e(Float.NaN)), androidx.compose.runtime.internal.e.e(-1980806532, new Y(qVar, c4832z, z3, z, function02, dVar3, c0555x, lVar2, dVar4, l2, dVar2, f, a0), c0814p), c0814p, 56);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new U(z, function0, z2, dVar, l, dVar2, c4832z, dVar3, c0555x, f, a0, lVar, qVar, i, i2, 0);
        }
    }

    public static final void d(Function0 onClick, boolean z, androidx.compose.runtime.internal.d label, androidx.compose.ui.text.L labelTextStyle, androidx.compose.runtime.internal.d dVar, S colors, androidx.compose.foundation.shape.d shape, float f, A0 paddingValues, androidx.compose.foundation.interaction.l lVar, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        boolean z2;
        androidx.compose.runtime.internal.d dVar2;
        float f2;
        int i4;
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        Intrinsics.checkNotNullParameter(label, "label");
        Intrinsics.checkNotNullParameter(labelTextStyle, "labelTextStyle");
        Intrinsics.checkNotNullParameter(colors, "colors");
        Intrinsics.checkNotNullParameter(shape, "shape");
        Intrinsics.checkNotNullParameter(paddingValues, "paddingValues");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-68283217);
        if ((i & 6) == 0) {
            i3 = (c0814p.h(onClick) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            z2 = z;
            i3 |= c0814p.g(z2) ? 32 : 16;
        } else {
            z2 = z;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p.h(label) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p.f(labelTextStyle) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            dVar2 = dVar;
            i3 |= c0814p.h(dVar2) ? 16384 : 8192;
        } else {
            dVar2 = dVar;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p.f(colors) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i3 |= c0814p.f(shape) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i3 |= c0814p.f(null) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            f2 = f;
            i3 |= c0814p.c(f2) ? 67108864 : 33554432;
        } else {
            f2 = f;
        }
        if ((i & 805306368) == 0) {
            i3 |= c0814p.f(paddingValues) ? 536870912 : 268435456;
        }
        if ((i2 & 6) == 0) {
            i4 = i2 | (c0814p.f(lVar) ? 4 : 2);
        } else {
            i4 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((306783379 & i3) == 306783378 && (i4 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            f(onClick, z2, label, labelTextStyle, dVar2, colors, shape, f2, paddingValues, lVar, qVar, c0814p, i3 & 2147483646, i4 & 126);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new T(onClick, z, label, labelTextStyle, dVar, colors, shape, f, paddingValues, lVar, qVar, i, i2, 1);
        }
    }

    public static final void e(final androidx.compose.runtime.internal.d dVar, final androidx.compose.ui.text.L l, final long j, final androidx.compose.runtime.internal.d dVar2, final long j2, final float f, final A0 a0, InterfaceC0806l interfaceC0806l, final int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1716079129);
        if (((i | (c0814p.h(dVar) ? 4 : 2) | (c0814p.f(l) ? 32 : 16) | (c0814p.e(j) ? 256 : 128) | (c0814p.h(dVar2) ? 2048 : 1024) | (c0814p.e(j2) ? 16384 : 8192) | (c0814p.c(f) ? 131072 : 65536) | (c0814p.f(a0) ? 1048576 : 524288)) & 599187) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0776c.b(new C0811n0[]{androidx.compose.animation.d0.j(j, AbstractC0669k0.a), Q4.a.a(l)}, androidx.compose.runtime.internal.e.e(-1971798311, new Z(f, a0, dVar2, dVar, j2), c0814p), c0814p, 56);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(l, j, dVar2, j2, f, a0, i) { // from class: com.quizlet.ui.compose.V
                public final /* synthetic */ androidx.compose.ui.text.L b;
                public final /* synthetic */ long c;
                public final /* synthetic */ androidx.compose.runtime.internal.d d;
                public final /* synthetic */ long e;
                public final /* synthetic */ float f;
                public final /* synthetic */ A0 g;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    float f2 = this.f;
                    A0 a02 = this.g;
                    c0.e(this.a, this.b, this.c, this.d, this.e, f2, a02, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void f(Function0 function0, boolean z, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.text.L l, androidx.compose.runtime.internal.d dVar2, S s, androidx.compose.foundation.shape.d dVar3, float f, A0 a0, androidx.compose.foundation.interaction.l lVar, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        Function0 function02;
        int i3;
        boolean z2;
        androidx.compose.runtime.internal.d dVar4;
        androidx.compose.ui.text.L l2;
        androidx.compose.runtime.internal.d dVar5;
        float f2;
        int i4;
        androidx.compose.foundation.interaction.l lVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1094116468);
        if ((i & 6) == 0) {
            function02 = function0;
            i3 = (c0814p.h(function02) ? 4 : 2) | i;
        } else {
            function02 = function0;
            i3 = i;
        }
        if ((i & 48) == 0) {
            z2 = z;
            i3 |= c0814p.g(z2) ? 32 : 16;
        } else {
            z2 = z;
        }
        if ((i & 384) == 0) {
            dVar4 = dVar;
            i3 |= c0814p.h(dVar4) ? 256 : 128;
        } else {
            dVar4 = dVar;
        }
        if ((i & 3072) == 0) {
            l2 = l;
            i3 |= c0814p.f(l2) ? 2048 : 1024;
        } else {
            l2 = l;
        }
        if ((i & 24576) == 0) {
            dVar5 = dVar2;
            i3 |= c0814p.h(dVar5) ? 16384 : 8192;
        } else {
            dVar5 = dVar2;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p.f(s) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i3 |= c0814p.f(dVar3) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i3 |= c0814p.f(null) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            f2 = f;
            i3 |= c0814p.c(f2) ? 67108864 : 33554432;
        } else {
            f2 = f;
        }
        if ((i & 805306368) == 0) {
            i3 |= c0814p.f(a0) ? 536870912 : 268435456;
        }
        if ((i2 & 6) == 0) {
            i4 = i2 | (c0814p.f(lVar) ? 4 : 2);
        } else {
            i4 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i3 & 306783379) == 306783378 && (i4 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(-900855982);
            if (lVar == null) {
                c0814p.X(-900855331);
                Object objI = c0814p.I();
                if (objI == C0804k.a) {
                    objI = androidx.compose.animation.d0.i(c0814p);
                }
                c0814p.p(false);
                lVar2 = (androidx.compose.foundation.interaction.l) objI;
            } else {
                lVar2 = lVar;
            }
            c0814p.p(false);
            C0776c.a(F1.a.a(new androidx.compose.ui.unit.e(Float.NaN)), androidx.compose.runtime.internal.e.e(-105381812, new b0(qVar, s, z2, function02, dVar3, lVar2, dVar4, l2, dVar5, f2, a0), c0814p), c0814p, 56);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new T(function0, z, dVar, l, dVar2, s, dVar3, f, a0, lVar, qVar, i, i2, 0);
        }
    }
}
