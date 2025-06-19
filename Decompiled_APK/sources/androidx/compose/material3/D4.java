package androidx.compose.material3;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3119d0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class D4 {
    public static final D4 a = new D4();
    public static final float b = 56;
    public static final float c = 280;
    public static final float d = 1;
    public static final float e = 2;

    public static A4 c(long j, long j2, long j3, long j4, long j5, long j6, long j7, long j8, long j9, long j10, androidx.compose.foundation.text.selection.p0 p0Var, long j11, long j12, long j13, long j14, long j15, long j16, long j17, long j18, long j19, long j20, long j21, long j22, long j23, long j24, long j25, InterfaceC0806l interfaceC0806l, int i) {
        long j26 = (i & 1) != 0 ? C0861v.g : j;
        long j27 = (i & 2) != 0 ? C0861v.g : j2;
        long j28 = (i & 4) != 0 ? C0861v.g : j3;
        long j29 = (i & 8) != 0 ? C0861v.g : j4;
        long j30 = (i & 64) != 0 ? C0861v.g : j7;
        long j31 = (i & 128) != 0 ? C0861v.g : j8;
        long j32 = (i & 256) != 0 ? C0861v.g : j9;
        long j33 = (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? C0861v.g : j10;
        androidx.compose.foundation.text.selection.p0 p0Var2 = (i & 1024) != 0 ? null : p0Var;
        long j34 = (i & 2048) != 0 ? C0861v.g : j11;
        long j35 = (i & 4096) != 0 ? C0861v.g : j12;
        long j36 = (i & 8192) != 0 ? C0861v.g : j13;
        long j37 = (i & 16384) != 0 ? C0861v.g : j14;
        long j38 = C0861v.g;
        long j39 = (262144 & i) != 0 ? j38 : j15;
        long j40 = (524288 & i) != 0 ? j38 : j16;
        long j41 = (1048576 & i) != 0 ? j38 : j17;
        long j42 = (4194304 & i) != 0 ? j38 : j18;
        long j43 = (8388608 & i) != 0 ? j38 : j19;
        long j44 = (16777216 & i) != 0 ? j38 : j20;
        long j45 = (67108864 & i) != 0 ? j38 : j21;
        long j46 = (134217728 & i) != 0 ? j38 : j22;
        long j47 = (268435456 & i) != 0 ? j38 : j23;
        long j48 = (536870912 & i) != 0 ? j38 : j24;
        long j49 = (i & 1073741824) != 0 ? j38 : j25;
        Z z = (Z) ((C0814p) interfaceC0806l).j(AbstractC0590b0.a);
        A4 a4 = z.W;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(27085453);
        if (a4 == null) {
            a4 = new A4(AbstractC0590b0.c(z, 18), AbstractC0590b0.c(z, 18), C0861v.b(AbstractC0590b0.c(z, 18), 0.38f), AbstractC0590b0.c(z, 18), AbstractC0590b0.c(z, 39), AbstractC0590b0.c(z, 39), AbstractC0590b0.c(z, 39), AbstractC0590b0.c(z, 39), AbstractC0590b0.c(z, 26), AbstractC0590b0.c(z, 2), (androidx.compose.foundation.text.selection.p0) c0814p.j(androidx.compose.foundation.text.selection.q0.a), AbstractC0590b0.c(z, 26), AbstractC0590b0.c(z, 19), C0861v.b(AbstractC0590b0.c(z, 18), 0.38f), AbstractC0590b0.c(z, 2), AbstractC0590b0.c(z, 19), AbstractC0590b0.c(z, 19), C0861v.b(AbstractC0590b0.c(z, 18), 0.38f), AbstractC0590b0.c(z, 19), AbstractC0590b0.c(z, 19), AbstractC0590b0.c(z, 19), C0861v.b(AbstractC0590b0.c(z, 18), 0.38f), AbstractC0590b0.c(z, 2), AbstractC0590b0.c(z, 26), AbstractC0590b0.c(z, 19), C0861v.b(AbstractC0590b0.c(z, 18), 0.38f), AbstractC0590b0.c(z, 2), AbstractC0590b0.c(z, 19), AbstractC0590b0.c(z, 19), C0861v.b(AbstractC0590b0.c(z, 18), 0.38f), AbstractC0590b0.c(z, 19), AbstractC0590b0.c(z, 19), AbstractC0590b0.c(z, 19), C0861v.b(AbstractC0590b0.c(z, 18), 0.38f), AbstractC0590b0.c(z, 2), AbstractC0590b0.c(z, 19), AbstractC0590b0.c(z, 19), C0861v.b(AbstractC0590b0.c(z, 19), 0.38f), AbstractC0590b0.c(z, 19), AbstractC0590b0.c(z, 19), AbstractC0590b0.c(z, 19), C0861v.b(AbstractC0590b0.c(z, 19), 0.38f), AbstractC0590b0.c(z, 19));
            z.W = a4;
        }
        c0814p.p(false);
        return a4.a(j26, j27, j28, j29, j5, j6, j30, j31, j32, j33, p0Var2, j34, j35, j36, j37, j38, j38, j38, j39, j40, j41, j38, j42, j43, j44, j38, j45, j46, j47, j48, j49, j38, j38, j38, j38, j38, j38, j38, j38, j38, j38, j38, j38);
    }

    public static androidx.compose.foundation.layout.A0 d() {
        float f = androidx.compose.material3.internal.Y.b;
        return new androidx.compose.foundation.layout.A0(f, androidx.compose.material3.internal.Y.d, f, 0);
    }

    public final void a(boolean z, boolean z2, androidx.compose.foundation.interaction.k kVar, A4 a4, androidx.compose.ui.graphics.V v, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-818661242);
        int i2 = i | (c0814p.g(z) ? 4 : 2) | (c0814p.g(z2) ? 32 : 16) | (c0814p.f(kVar) ? 256 : 128) | (c0814p.f(a4) ? 16384 : 8192) | (c0814p.f(v) ? 131072 : 65536);
        if ((38347923 & i2) == 38347922 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            C4 c4 = new C4(new androidx.compose.foundation.lazy.i(0, 4, androidx.compose.runtime.W0.class, androidx.compose.animation.i0.a(!z ? a4.g : z2 ? a4.h : ((Boolean) AbstractC3119d0.h(kVar, c0814p, (i2 >> 6) & 14).getValue()).booleanValue() ? a4.e : a4.f, AbstractC0240f.r(150, 0, null, 6), null, null, c0814p, 48, 12), "value", "getValue()Ljava/lang/Object;"));
            float f = androidx.compose.material3.internal.Y.b;
            AbstractC0409s.a(androidx.compose.ui.a.a(androidx.compose.ui.draw.g.f(nVar, new androidx.compose.foundation.text.selection.n0(10, v, c4)), new androidx.compose.foundation.selection.b(kVar, z, z2, a4)), c0814p, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new B4(this, z, z2, kVar, a4, v, i);
        }
    }

    public final void b(String str, Function2 function2, boolean z, boolean z2, androidx.compose.ui.text.input.K k, androidx.compose.foundation.interaction.k kVar, boolean z3, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, androidx.compose.runtime.internal.d dVar5, androidx.compose.ui.graphics.V v, A4 a4, androidx.compose.foundation.layout.A0 a0, androidx.compose.runtime.internal.d dVar6, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        androidx.compose.ui.text.input.K k2;
        boolean z4;
        androidx.compose.runtime.internal.d dVar7;
        androidx.compose.runtime.internal.d dVar8;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        androidx.compose.foundation.layout.A0 a02;
        androidx.compose.runtime.internal.d dVarE;
        androidx.compose.runtime.internal.d dVar9;
        androidx.compose.runtime.internal.d dVar10;
        androidx.compose.runtime.internal.d dVar11;
        androidx.compose.runtime.internal.d dVar12;
        boolean z5;
        androidx.compose.foundation.layout.A0 a03;
        int i9;
        androidx.compose.foundation.layout.A0 a04;
        C0814p c0814p;
        androidx.compose.runtime.internal.d dVar13;
        androidx.compose.runtime.internal.d dVar14;
        androidx.compose.foundation.layout.A0 a05;
        androidx.compose.runtime.internal.d dVar15;
        androidx.compose.runtime.internal.d dVar16;
        androidx.compose.runtime.internal.d dVar17;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(289640444);
        if ((i & 6) == 0) {
            i3 = (c0814p2.f(str) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p2.h(function2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p2.g(z) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p2.g(z2) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            k2 = k;
            i3 |= c0814p2.f(k2) ? 16384 : 8192;
        } else {
            k2 = k;
        }
        if ((i & 196608) == 0) {
            i3 |= c0814p2.f(kVar) ? 131072 : 65536;
        }
        int i10 = i2 & 64;
        int i11 = 524288;
        if (i10 != 0) {
            i3 |= 1572864;
            z4 = z3;
        } else {
            z4 = z3;
            if ((i & 1572864) == 0) {
                i3 |= c0814p2.g(z4) ? 1048576 : 524288;
            }
        }
        int i12 = i2 & 128;
        if (i12 != 0) {
            i3 |= 12582912;
            dVar7 = dVar;
        } else {
            dVar7 = dVar;
            if ((i & 12582912) == 0) {
                i3 |= c0814p2.h(dVar7) ? 8388608 : 4194304;
            }
        }
        int i13 = i2 & 256;
        if (i13 != 0) {
            i3 |= 100663296;
            dVar8 = dVar2;
        } else {
            dVar8 = dVar2;
            if ((i & 100663296) == 0) {
                i3 |= c0814p2.h(dVar8) ? 67108864 : 33554432;
            }
        }
        int i14 = i2 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
        if (i14 != 0) {
            i3 |= 805306368;
        } else if ((i & 805306368) == 0) {
            i3 |= c0814p2.h(dVar3) ? 536870912 : 268435456;
        }
        int i15 = i2 & 1024;
        if (i15 != 0) {
            i5 = 100663302;
            i4 = i15;
        } else {
            i4 = i15;
            i5 = 100663296 | (c0814p2.h(dVar4) ? 4 : 2);
        }
        if ((i2 & 2048) != 0) {
            i6 = i5 | 48;
        } else {
            i6 = i5 | (c0814p2.h(null) ? 32 : 16);
        }
        int i16 = i6;
        if ((i2 & 4096) != 0) {
            i7 = i16 | 384;
        } else {
            i7 = i16 | (c0814p2.h(null) ? 256 : 128);
        }
        int i17 = i2 & 8192;
        if (i17 != 0) {
            i8 = i7 | 3072;
        } else {
            i8 = i7 | (c0814p2.h(dVar5) ? 2048 : 1024);
        }
        int i18 = i8 | (c0814p2.f(v) ? 16384 : 8192) | (c0814p2.f(a4) ? 131072 : 65536);
        if ((i2 & 65536) == 0 && c0814p2.f(a0)) {
            i11 = 1048576;
        }
        int i19 = i18 | i11 | 12582912;
        if ((i3 & 306783379) == 306783378 && (i19 & 38347923) == 38347922 && c0814p2.x()) {
            c0814p2.Q();
            dVar14 = dVar4;
            a05 = a0;
            dVarE = dVar6;
            c0814p = c0814p2;
            dVar15 = dVar7;
            dVar17 = dVar8;
            dVar13 = dVar3;
            dVar16 = dVar5;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                boolean z6 = i10 != 0 ? false : z4;
                if (i12 != 0) {
                    dVar7 = null;
                }
                androidx.compose.runtime.internal.d dVar18 = i13 != 0 ? null : dVar8;
                androidx.compose.runtime.internal.d dVar19 = i14 != 0 ? null : dVar3;
                androidx.compose.runtime.internal.d dVar20 = i4 != 0 ? null : dVar4;
                androidx.compose.runtime.internal.d dVar21 = i17 != 0 ? null : dVar5;
                if ((i2 & 65536) != 0) {
                    if (dVar7 == null) {
                        float f = androidx.compose.material3.internal.Y.b;
                        a04 = new androidx.compose.foundation.layout.A0(f, f, f, f);
                        i9 = -3670017;
                    } else {
                        float f2 = androidx.compose.material3.internal.Y.b;
                        float f3 = K4.a;
                        i9 = -3670017;
                        a04 = new androidx.compose.foundation.layout.A0(f2, f3, f2, f3);
                    }
                    i19 &= i9;
                    a02 = a04;
                } else {
                    a02 = a0;
                }
                int i20 = i19;
                boolean z7 = z6;
                dVarE = androidx.compose.runtime.internal.e.e(-435523791, new U2(z, z7, kVar, a4, v, 2), c0814p2);
                dVar9 = dVar21;
                dVar10 = dVar18;
                dVar11 = dVar19;
                dVar12 = dVar20;
                z5 = z7;
                i19 = i20;
                a03 = a02;
            } else {
                c0814p2.Q();
                if ((i2 & 65536) != 0) {
                    i19 &= -3670017;
                }
                dVar12 = dVar4;
                dVar9 = dVar5;
                a03 = a0;
                dVarE = dVar6;
                dVar10 = dVar8;
                z5 = z4;
                dVar11 = dVar3;
            }
            c0814p2.q();
            c0814p = c0814p2;
            androidx.compose.material3.internal.Z z8 = androidx.compose.material3.internal.Z.a;
            int i21 = i3 << 3;
            int i22 = (i21 & 896) | (i21 & ContentType.LONG_FORM_ON_DEMAND) | 6;
            int i23 = i3 >> 3;
            int i24 = i3 >> 9;
            int i25 = i19 << 21;
            int i26 = ((i19 >> 9) & 14) | ((i3 >> 6) & ContentType.LONG_FORM_ON_DEMAND) | (i3 & 896) | (i24 & 7168) | (i23 & 57344) | ((i19 >> 3) & 458752) | (3670016 & (i19 << 3)) | 12582912;
            androidx.compose.runtime.internal.d dVar22 = dVar7;
            androidx.compose.material3.internal.Y.a(z8, str, function2, k2, dVar22, dVar10, dVar11, dVar12, dVar9, z2, z, z5, kVar, a03, a4, dVarE, c0814p, i22 | (i23 & 7168) | (57344 & i24) | (458752 & i24) | (3670016 & i24) | (29360128 & i25) | (234881024 & i25) | (i25 & 1879048192), i26);
            dVar13 = dVar11;
            dVar14 = dVar12;
            z4 = z5;
            a05 = a03;
            dVar15 = dVar22;
            dVar16 = dVar9;
            dVar17 = dVar10;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new W2(this, str, function2, z, z2, k, kVar, z4, dVar15, dVar17, dVar13, dVar14, dVar16, v, a4, a05, dVarE, i, i2);
        }
    }
}
