package androidx.compose.material3;

import androidx.compose.animation.C0229c;
import androidx.compose.animation.C0281h;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0404p;
import androidx.compose.foundation.text.C0504k0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.q4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0709q4 {
    public static final float a;
    public static final float b;
    public static final float c;
    public static final float d;
    public static final long e;

    static {
        float f = androidx.compose.material3.tokens.u.a;
        a = androidx.compose.material3.tokens.u.b;
        b = 16;
        c = 14;
        d = 6;
        e = S5.g(20);
    }

    public static final void a(int i, long j, long j2, InterfaceC0806l interfaceC0806l, androidx.compose.runtime.internal.d dVar, Function0 function0, boolean z, boolean z2) {
        int i2;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-202735880);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(nVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.g(z2) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.e(j) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.e(j2) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.f(null) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.h(dVar) ? 8388608 : 4194304;
        }
        int i3 = i2;
        if ((4793491 & i3) == 4793490 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            int i4 = i3 >> 12;
            c0814p = c0814p;
            c(j, j2, z, androidx.compose.runtime.internal.e.e(-551896140, new U2(z, AbstractC0696o3.c(true, DefinitionKt.NO_Float_VALUE, j, c0814p, ((i3 >> 6) & 896) | 6, 2), z2, function0, dVar), c0814p), c0814p, (i4 & ContentType.LONG_FORM_ON_DEMAND) | (i4 & 14) | 3072 | ((i3 << 6) & 896));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0691n4(z, function0, z2, j, j2, dVar, i);
        }
    }

    public static final void b(int i, long j, long j2, InterfaceC0806l interfaceC0806l, androidx.compose.runtime.internal.d dVar, Function0 function0, boolean z, boolean z2) {
        boolean z3;
        int i2;
        Function0 function02;
        boolean z4;
        boolean z5;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-350627181);
        if ((i & 6) == 0) {
            z3 = z;
            i2 = (c0814p.g(z3) ? 4 : 2) | i;
        } else {
            z3 = z;
            i2 = i;
        }
        if ((i & 48) == 0) {
            function02 = function0;
            i2 |= c0814p.h(function02) ? 32 : 16;
        } else {
            function02 = function0;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(nVar) ? 256 : 128;
        }
        int i3 = i2 | 3072;
        if ((i & 24576) == 0) {
            i3 |= c0814p.h(dVar) ? 16384 : 8192;
        }
        int i4 = i3 | 196608;
        if ((1572864 & i) == 0) {
            i4 |= c0814p.e(j) ? 1048576 : 524288;
        }
        if ((i & 12582912) == 0) {
            i4 |= c0814p.e(j2) ? 8388608 : 4194304;
        }
        int i5 = i4 | 100663296;
        if ((38347923 & i5) == 38347922 && c0814p.x()) {
            c0814p.Q();
            z5 = z2;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                z4 = true;
            } else {
                c0814p.Q();
                z4 = z2;
            }
            c0814p.q();
            c0814p.X(79583089);
            androidx.compose.runtime.internal.d dVarE = dVar == null ? null : androidx.compose.runtime.internal.e.e(708874428, new C0281h(dVar, 19), c0814p);
            c0814p.p(false);
            androidx.compose.runtime.internal.d dVarE2 = androidx.compose.runtime.internal.e.e(1540996038, new C0685m4(dVarE, 0), c0814p);
            int i6 = 12582912 | (i5 & 14) | (i5 & ContentType.LONG_FORM_ON_DEMAND) | (i5 & 896) | (i5 & 7168);
            int i7 = i5 >> 6;
            a(i6 | (57344 & i7) | (458752 & i7) | (i7 & 3670016), j, j2, c0814p, dVarE2, function02, z3, z4);
            z5 = z4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0691n4(z, function0, z5, dVar, j, j2, i);
        }
    }

    public static final void c(long j, long j2, boolean z, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        long j3;
        int i3;
        boolean z2;
        androidx.compose.animation.core.K0 k0R;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(735731848);
        if ((i & 6) == 0) {
            i2 = (c0814p.e(j) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            j3 = j2;
            i2 |= c0814p.e(j3) ? 32 : 16;
        } else {
            j3 = j2;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(dVar) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i4 = i2 >> 6;
            androidx.compose.animation.core.E0 e0D = androidx.compose.animation.core.I0.d(Boolean.valueOf(z), null, c0814p, i4 & 14, 2);
            androidx.compose.runtime.L0 l0 = (androidx.compose.runtime.L0) e0D.d;
            boolean zBooleanValue = ((Boolean) l0.getValue()).booleanValue();
            c0814p.X(-1997025499);
            long j4 = zBooleanValue ? j : j3;
            c0814p.p(false);
            androidx.compose.ui.graphics.colorspace.c cVarF = C0861v.f(j4);
            boolean zF = c0814p.f(cVarF);
            Object objI = c0814p.I();
            if (zF || objI == C0804k.a) {
                C0229c c0229c = C0229c.g;
                androidx.camera.lifecycle.f fVar = new androidx.camera.lifecycle.f(cVarF, 3);
                androidx.compose.animation.core.L0 l02 = androidx.compose.animation.core.M0.a;
                androidx.compose.animation.core.L0 l03 = new androidx.compose.animation.core.L0(c0229c, fVar);
                c0814p.i0(l03);
                objI = l03;
            }
            androidx.compose.animation.core.L0 l04 = (androidx.compose.animation.core.L0) objI;
            boolean zBooleanValue2 = ((Boolean) e0D.a.t()).booleanValue();
            c0814p.X(-1997025499);
            C0861v c0861vK = androidx.compose.animation.d0.k(c0814p, false, zBooleanValue2 ? j : j3);
            boolean zBooleanValue3 = ((Boolean) l0.getValue()).booleanValue();
            c0814p.X(-1997025499);
            C0861v c0861vK2 = androidx.compose.animation.d0.k(c0814p, false, zBooleanValue3 ? j : j3);
            androidx.compose.animation.core.x0 x0VarF = e0D.f();
            c0814p.X(-899623535);
            if (x0VarF.b(Boolean.FALSE, Boolean.TRUE)) {
                i3 = i4;
                k0R = new androidx.compose.animation.core.K0(150, 100, androidx.compose.animation.core.C.d);
                z2 = false;
            } else {
                i3 = i4;
                z2 = false;
                k0R = AbstractC0240f.r(100, 0, androidx.compose.animation.core.C.d, 2);
            }
            c0814p.p(z2);
            C0776c.a(androidx.compose.animation.d0.j(((C0861v) androidx.compose.animation.core.I0.b(e0D, c0861vK, c0861vK2, k0R, l04, c0814p, 0).getValue()).a, AbstractC0669k0.a), dVar, c0814p, (i3 & ContentType.LONG_FORM_ON_DEMAND) | 8);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0703p4(j, j3, z, dVar, i);
        }
    }

    public static final void d(androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(514131524);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(dVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(null) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i3 = i2 & 14;
            boolean z = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | (i3 == 4);
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new C0504k0(dVar, 1);
                c0814p.i0(objI);
            }
            androidx.compose.ui.layout.K k = (androidx.compose.ui.layout.K) objI;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, k, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            c0814p.X(871566271);
            androidx.compose.ui.i iVar = androidx.compose.ui.b.a;
            if (dVar != null) {
                androidx.compose.ui.q qVarW = AbstractC0382e.w(AbstractC0897s.k(nVar, "text"), b, DefinitionKt.NO_Float_VALUE, 2);
                androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, false);
                int i5 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
                androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarW);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                    android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
                }
                C0776c.E(c0814p, qVarC2, c0912h4);
                androidx.compose.animation.d0.w(i3, dVar, c0814p, true);
            }
            c0814p.p(false);
            c0814p.X(871570579);
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0404p(dVar, i, 4);
        }
    }
}
