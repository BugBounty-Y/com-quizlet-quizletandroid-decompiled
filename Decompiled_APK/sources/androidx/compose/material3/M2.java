package androidx.compose.material3;

import androidx.compose.animation.C0281h;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.AbstractC0248j;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class M2 {
    public static final float a;
    public static final float b;
    public static final float c;
    public static final float d;
    public static final float e;
    public static final float f;

    static {
        float f2 = androidx.compose.material3.tokens.q.a;
        a = androidx.compose.material3.tokens.q.c;
        b = 8;
        c = 4;
        float f3 = androidx.compose.material3.tokens.q.b;
        float f4 = androidx.compose.material3.tokens.q.d;
        float f5 = 2;
        d = (f3 - f4) / f5;
        e = (androidx.compose.material3.tokens.q.a - f4) / f5;
        f = 12;
    }

    public static final void a(androidx.compose.ui.q qVar, long j, long j2, float f2, C0416v0 c0416v0, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        long j3;
        C0416v0 c0416v02;
        float f3;
        androidx.compose.runtime.internal.d dVar2;
        C0416v0 c0416v03;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1596802123);
        int i3 = i | (c0814p.f(qVar) ? 4 : 2) | (c0814p.e(j) ? 32 : 16) | 11392;
        if ((74899 & i3) == 74898 && c0814p.x()) {
            c0814p.Q();
            j3 = j2;
            f3 = f2;
            c0416v03 = c0416v0;
            dVar2 = dVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                long jA = AbstractC0590b0.a((Z) c0814p.j(AbstractC0590b0.a), j);
                float f4 = C2.a;
                WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
                i2 = i3 & (-58241);
                j3 = jA;
                c0416v02 = new C0416v0(C0380d.e(c0814p).g, 32 | AbstractC0382e.g);
                f3 = f4;
            } else {
                c0814p.Q();
                i2 = i3 & (-58241);
                j3 = j2;
                f3 = f2;
                c0416v02 = c0416v0;
            }
            c0814p.q();
            dVar2 = dVar;
            AbstractC0594b4.a(qVar, null, j, j3, f3, DefinitionKt.NO_Float_VALUE, null, androidx.compose.runtime.internal.e.e(105663120, new androidx.compose.foundation.contextmenu.i(17, c0416v02, dVar2), c0814p), c0814p, ((i2 << 3) & 896) | (i2 & 14) | 12582912 | 24576, 98);
            c0416v03 = c0416v02;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new E2(qVar, j, j3, f3, c0416v03, dVar2, i);
        }
    }

    public static final void b(androidx.compose.foundation.layout.H0 h0, boolean z, Function0 function0, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, boolean z2, androidx.compose.runtime.internal.d dVar2, boolean z3, D2 d2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.q qVar2;
        boolean z4;
        boolean z5;
        C0814p c0814p;
        boolean z6;
        boolean z7;
        androidx.compose.ui.q qVar3;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-663510974);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(h0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function0) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(dVar) ? 2048 : 1024;
        }
        int i3 = i2 | 221184;
        if ((1572864 & i) == 0) {
            i3 |= c0814p2.h(dVar2) ? 1048576 : 524288;
        }
        int i4 = i3 | 12582912;
        if ((100663296 & i) == 0) {
            i4 |= c0814p2.f(d2) ? 67108864 : 33554432;
        }
        int i5 = i4 | 805306368;
        if ((i5 & 306783379) == 306783378 && c0814p2.x()) {
            c0814p2.Q();
            qVar3 = qVar;
            z7 = z2;
            z6 = z3;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                qVar2 = androidx.compose.ui.n.b;
                z4 = true;
                z5 = true;
            } else {
                c0814p2.Q();
                qVar2 = qVar;
                z4 = z2;
                z5 = z3;
            }
            c0814p2.q();
            c0814p2.X(-103236853);
            Object obj = C0804k.a;
            Object objI = c0814p2.I();
            if (objI == obj) {
                objI = androidx.compose.animation.d0.i(c0814p2);
            }
            androidx.compose.foundation.interaction.l lVar = (androidx.compose.foundation.interaction.l) objI;
            c0814p2.p(false);
            boolean z8 = z5;
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-1419576100, new H2(d2, z, z4, dVar2, z5, dVar), c0814p2);
            c0814p2.X(-103210706);
            androidx.compose.runtime.internal.d dVarE2 = dVar2 == null ? null : androidx.compose.runtime.internal.e.e(1644987592, new I2(d2, z, z4, dVar2), c0814p2);
            c0814p2.p(false);
            Object objI2 = c0814p2.I();
            if (objI2 == obj) {
                objI2 = C0776c.w(0);
                c0814p2.i0(objI2);
            }
            androidx.compose.runtime.H0 h02 = (androidx.compose.runtime.H0) objI2;
            boolean z9 = z4;
            androidx.compose.ui.q qVar4 = qVar2;
            androidx.compose.ui.q qVarA = h0.a(androidx.compose.foundation.layout.K0.b(androidx.compose.foundation.selection.d.a(qVar4, z, lVar, null, z9, new androidx.compose.ui.semantics.h(4), function0), DefinitionKt.NO_Float_VALUE, a, 1), 1.0f, true);
            Object objI3 = c0814p2.I();
            if (objI3 == obj) {
                objI3 = new F2(h02, 0);
                c0814p2.i0(objI3);
            }
            androidx.compose.ui.q qVarM = AbstractC0897s.m(qVarA, (Function1) objI3);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.e, true);
            int i6 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarM);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, kE, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p2, i6, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.runtime.W0 w0B = AbstractC0248j.b(z ? 1.0f : DefinitionKt.NO_Float_VALUE, AbstractC0240f.r(100, 0, null, 6), null, null, c0814p2, 48, 28);
            long jC = com.google.android.gms.internal.mlkit_vision_barcode.Q4.c((h02.i() - r3.m0(androidx.compose.material3.tokens.q.b)) / 2, ((androidx.compose.ui.unit.b) c0814p2.j(AbstractC0955m0.f)).c0(f));
            Unit unit = Unit.a;
            boolean zF = c0814p2.f(lVar) | c0814p2.e(jC);
            Object objI4 = c0814p2.I();
            if (zF || objI4 == obj) {
                objI4 = new androidx.compose.material3.internal.I(lVar, jC);
                c0814p2.i0(objI4);
            }
            int i7 = 18;
            androidx.compose.runtime.internal.d dVarE3 = androidx.compose.runtime.internal.e.e(691730997, new C0281h((androidx.compose.material3.internal.I) objI4, i7), c0814p2);
            androidx.compose.runtime.internal.d dVarE4 = androidx.compose.runtime.internal.e.e(-474426875, new androidx.compose.foundation.contextmenu.i(i7, w0B, d2), c0814p2);
            boolean zF2 = c0814p2.f(w0B);
            Object objI5 = c0814p2.I();
            if (zF2 || objI5 == obj) {
                objI5 = new androidx.compose.foundation.text.selection.L(w0B, 1);
                c0814p2.i0(objI5);
            }
            c(dVarE3, dVarE4, dVarE, dVarE2, z8, (Function0) objI5, c0814p2, ((i5 >> 9) & 57344) | 438);
            c0814p2.p(true);
            c0814p = c0814p2;
            z6 = z8;
            z7 = z9;
            qVar3 = qVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new O0(h0, z, function0, dVar, qVar3, z7, dVar2, z6, d2, i);
        }
    }

    public static final void c(androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, boolean z, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z2;
        Function0 function02;
        boolean z3;
        androidx.compose.runtime.internal.d dVar5 = dVar4;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1427075886);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(dVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(dVar2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(dVar3) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(dVar5) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.g(z) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function0) ? 131072 : 65536;
        }
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
            z2 = z;
            function02 = function0;
        } else {
            int i3 = 458752 & i2;
            int i4 = 57344 & i2;
            boolean z4 = ((i2 & 7168) == 2048) | (i3 == 131072) | (i4 == 16384);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z4 || objI == v) {
                objI = new J2(function0, dVar5, z);
                c0814p.i0(objI);
            }
            androidx.compose.ui.layout.K k = (androidx.compose.ui.layout.K) objI;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
            InterfaceC0915k.D0.getClass();
            int i6 = i2;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            dVar.invoke(c0814p, Integer.valueOf(i6 & 14));
            dVar2.invoke(c0814p, Integer.valueOf((i6 >> 3) & 14));
            androidx.compose.ui.q qVarK = AbstractC0897s.k(nVar, "icon");
            androidx.compose.ui.i iVar = androidx.compose.ui.b.a;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, false);
            int i7 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarK);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            dVar3.invoke(c0814p, Integer.valueOf((i6 >> 6) & 14));
            c0814p.p(true);
            c0814p.X(1087196576);
            if (dVar4 != null) {
                androidx.compose.ui.q qVarK2 = AbstractC0897s.k(nVar, "label");
                boolean z5 = (i4 == 16384) | (i3 == 131072);
                Object objI2 = c0814p.I();
                if (z5 || objI2 == v) {
                    z2 = z;
                    function02 = function0;
                    objI2 = new androidx.compose.animation.T(z2, function02, 1);
                    c0814p.i0(objI2);
                } else {
                    z2 = z;
                    function02 = function0;
                }
                androidx.compose.ui.q qVarP = androidx.compose.ui.graphics.F.p(qVarK2, (Function1) objI2);
                androidx.compose.ui.layout.K kE2 = AbstractC0409s.e(iVar, false);
                int i8 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
                androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarP);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE2, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                    android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
                }
                C0776c.E(c0814p, qVarC3, c0912h4);
                dVar5 = dVar4;
                z3 = true;
                androidx.compose.animation.d0.w((i6 >> 9) & 14, dVar5, c0814p, true);
            } else {
                dVar5 = dVar4;
                z2 = z;
                function02 = function0;
                z3 = true;
            }
            c0814p.p(false);
            c0814p.p(z3);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new W1(dVar, dVar2, dVar3, dVar5, z2, function02, i);
        }
    }
}
