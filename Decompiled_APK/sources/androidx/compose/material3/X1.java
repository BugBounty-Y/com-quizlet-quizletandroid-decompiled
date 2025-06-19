package androidx.compose.material3;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.gestures.C0346q0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0976x0;
import com.comscore.streaming.ContentType;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class X1 {
    public static final float a;
    public static final float b;
    public static final float c = 12;
    public static final float d = 8;
    public static final float e = ContentType.LONG_FORM_ON_DEMAND;
    public static final float f = 280;

    static {
        float f2 = 48;
        a = f2;
        b = f2;
    }

    public static final void a(androidx.compose.ui.q qVar, androidx.compose.animation.core.T t, InterfaceC0773a0 interfaceC0773a0, androidx.compose.foundation.N0 n0, androidx.compose.ui.graphics.V v, long j, float f2, float f3, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        Float f4;
        boolean z;
        androidx.compose.animation.core.K0 k0R;
        boolean z2;
        boolean z3;
        androidx.compose.animation.core.K0 k0R2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-151448888);
        int i2 = i | (c0814p2.f(qVar) ? 4 : 2) | (c0814p2.f(t) ? 32 : 16) | (c0814p2.f(n0) ? 2048 : 1024) | (c0814p2.f(v) ? 16384 : 8192) | (c0814p2.e(j) ? 131072 : 65536) | (c0814p2.c(f2) ? 1048576 : 524288) | (c0814p2.c(f3) ? 8388608 : 4194304) | (c0814p2.f(null) ? 67108864 : 33554432) | (c0814p2.h(dVar) ? 536870912 : 268435456);
        if ((i2 & 306783379) == 306783378 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.animation.core.E0 e0C = androidx.compose.animation.core.I0.c(t, "DropDownMenu", c0814p2, (((i2 >> 3) & 14) | 48) & 126);
            androidx.compose.animation.core.L0 l0 = androidx.compose.animation.core.M0.a;
            boolean zBooleanValue = ((Boolean) e0C.a.t()).booleanValue();
            c0814p2.X(2139028452);
            float f5 = zBooleanValue ? 1.0f : 0.8f;
            c0814p2.p(false);
            Float fValueOf = Float.valueOf(f5);
            androidx.compose.runtime.L0 l02 = (androidx.compose.runtime.L0) e0C.d;
            boolean zBooleanValue2 = ((Boolean) l02.getValue()).booleanValue();
            c0814p2.X(2139028452);
            float f6 = zBooleanValue2 ? 1.0f : 0.8f;
            c0814p2.p(false);
            Float fValueOf2 = Float.valueOf(f6);
            androidx.compose.animation.core.x0 x0VarF = e0C.f();
            c0814p2.X(1033023423);
            Boolean bool = Boolean.FALSE;
            Boolean bool2 = Boolean.TRUE;
            if (x0VarF.b(bool, bool2)) {
                f4 = fValueOf2;
                k0R = AbstractC0240f.r(120, 0, androidx.compose.animation.core.C.b, 2);
                z2 = false;
                z = true;
            } else {
                f4 = fValueOf2;
                z = true;
                k0R = AbstractC0240f.r(1, 74, null, 4);
                z2 = false;
            }
            c0814p2.p(z2);
            androidx.compose.animation.core.z0 z0VarB = androidx.compose.animation.core.I0.b(e0C, fValueOf, f4, k0R, l0, c0814p2, 0);
            boolean zBooleanValue3 = ((Boolean) e0C.a.t()).booleanValue();
            c0814p2.X(-249413128);
            float f7 = zBooleanValue3 ? 1.0f : 0.0f;
            c0814p2.p(false);
            Float fValueOf3 = Float.valueOf(f7);
            boolean zBooleanValue4 = ((Boolean) l02.getValue()).booleanValue();
            c0814p2.X(-249413128);
            float f8 = zBooleanValue4 ? 1.0f : 0.0f;
            c0814p2.p(false);
            Float fValueOf4 = Float.valueOf(f8);
            androidx.compose.animation.core.x0 x0VarF2 = e0C.f();
            c0814p2.X(-1355418157);
            if (x0VarF2.b(bool, bool2)) {
                z3 = false;
                k0R2 = AbstractC0240f.r(30, 0, null, 6);
            } else {
                z3 = false;
                k0R2 = AbstractC0240f.r(75, 0, null, 6);
            }
            androidx.compose.animation.core.K0 k0 = k0R2;
            c0814p2.p(z3);
            androidx.compose.animation.core.z0 z0VarB2 = androidx.compose.animation.core.I0.b(e0C, fValueOf3, fValueOf4, k0, l0, c0814p2, 0);
            boolean zBooleanValue5 = ((Boolean) c0814p2.j(AbstractC0976x0.a)).booleanValue();
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            boolean zG = c0814p2.g(zBooleanValue5) | c0814p2.f(z0VarB);
            if ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) {
                z3 = z;
            }
            boolean zF = zG | z3 | c0814p2.f(z0VarB2);
            Object objI = c0814p2.I();
            if (zF || objI == C0804k.a) {
                U1 u1 = new U1(zBooleanValue5, t, interfaceC0773a0, z0VarB, z0VarB2);
                c0814p2.i0(u1);
                objI = u1;
            }
            int i3 = i2 >> 9;
            int i4 = i2 >> 6;
            AbstractC0594b4.a(androidx.compose.ui.graphics.F.p(nVar, (Function1) objI), v, j, 0L, f2, f3, null, androidx.compose.runtime.internal.e.e(1573559053, new C0346q0(qVar, n0, dVar, 4), c0814p2), c0814p2, (i3 & 896) | (i3 & ContentType.LONG_FORM_ON_DEMAND) | 12582912 | (57344 & i4) | (458752 & i4) | (i4 & 3670016), 8);
            c0814p = c0814p2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0662j(qVar, t, interfaceC0773a0, n0, v, j, f2, f3, dVar, i);
        }
    }

    public static final void b(androidx.compose.runtime.internal.d dVar, Function0 function0, androidx.compose.ui.n nVar, boolean z, T1 t1, androidx.compose.foundation.layout.A0 a0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z2 = z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1564716777);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(dVar) ? 4 : 2) | i;
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
            i2 |= c0814p.h(null) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(null) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.g(z2) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.f(t1) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.f(a0) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i2 |= c0814p.f(null) ? 67108864 : 33554432;
        }
        if ((i2 & 38347923) == 38347922 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarK = AbstractC0460p.k(nVar, null, AbstractC0696o3.c(true, DefinitionKt.NO_Float_VALUE, 0L, c0814p, 6, 6), z2, null, function0, 24);
            z2 = z2;
            androidx.compose.ui.q qVarT = AbstractC0382e.t(androidx.compose.foundation.layout.K0.n(androidx.compose.foundation.layout.K0.c(qVarK, 1.0f), e, b, f, DefinitionKt.NO_Float_VALUE, 8), a0);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarT);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            Q4.a(((Y4) c0814p.j(Z4.a)).m, androidx.compose.runtime.internal.e.e(1065051884, new V1(t1, z2, dVar), c0814p), c0814p, 48);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new W1(dVar, function0, nVar, z2, t1, a0, i);
        }
    }
}
