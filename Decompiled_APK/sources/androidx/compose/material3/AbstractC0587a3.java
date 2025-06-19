package androidx.compose.material3;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.text.C0488f0;
import androidx.compose.foundation.text.C0490g0;
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
import com.comscore.streaming.ContentType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3119d0;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import com.google.android.gms.internal.mlkit_vision_barcode.V5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.a3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0587a3 {
    public static final float a = 4;
    public static final long b;

    static {
        long j = androidx.compose.material3.tokens.E.l;
        if (S5.h(j)) {
            throw new IllegalArgumentException("Cannot perform operation for Unspecified type.");
        }
        b = S5.i(1095216660480L & j, androidx.compose.ui.unit.m.c(j) / 2);
    }

    public static final void a(androidx.compose.ui.text.input.A a2, Function1 function1, androidx.compose.ui.q qVar, boolean z, androidx.compose.ui.text.L l, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, boolean z2, androidx.compose.ui.text.input.K k, C0490g0 c0490g0, C0488f0 c0488f0, boolean z3, int i, int i2, androidx.compose.ui.graphics.V v, A4 a4, InterfaceC0806l interfaceC0806l, int i3) {
        int i4;
        Function1 function12;
        androidx.compose.ui.q qVar2;
        androidx.compose.runtime.internal.d dVar4;
        androidx.compose.runtime.internal.d dVar5;
        androidx.compose.ui.text.L l2;
        int i5;
        androidx.compose.ui.graphics.V vA;
        int i6;
        C0488f0 c0488f02;
        C0488f0 c0488f03;
        int i7;
        boolean z4;
        androidx.compose.ui.graphics.V v2;
        androidx.compose.ui.text.L l3;
        int i8;
        boolean z5 = true;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1570442800);
        if ((i3 & 6) == 0) {
            i4 = (c0814p.f(a2) ? 4 : 2) | i3;
        } else {
            i4 = i3;
        }
        if ((i3 & 48) == 0) {
            function12 = function1;
            i4 |= c0814p.h(function12) ? 32 : 16;
        } else {
            function12 = function1;
        }
        if ((i3 & 384) == 0) {
            qVar2 = qVar;
            i4 |= c0814p.f(qVar2) ? 256 : 128;
        } else {
            qVar2 = qVar;
        }
        int i9 = i4 | 27648;
        if ((196608 & i3) == 0) {
            i9 = 93184 | i4;
        }
        if ((1572864 & i3) == 0) {
            dVar4 = dVar;
            i9 |= c0814p.h(dVar4) ? 1048576 : 524288;
        } else {
            dVar4 = dVar;
        }
        if ((12582912 & i3) == 0) {
            dVar5 = dVar2;
            i9 |= c0814p.h(dVar5) ? 8388608 : 4194304;
        } else {
            dVar5 = dVar2;
        }
        int i10 = i9 | 905969664;
        int i11 = (c0814p.g(z2) ? (char) 2048 : (char) 1024) | 438 | (c0814p.f(k) ? 16384 : 8192) | 840433664;
        int i12 = (c0814p.f(a4) ? (char) 256 : (char) 128) | 22;
        if ((i10 & 306783379) == 306783378 && (306783379 & i11) == 306783378 && (i12 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            z4 = z;
            l3 = l;
            c0488f03 = c0488f0;
            i8 = i;
            i7 = i2;
            v2 = v;
        } else {
            c0814p.S();
            if ((i3 & 1) == 0 || c0814p.w()) {
                l2 = (androidx.compose.ui.text.L) c0814p.j(Q4.a);
                C0488f0 c0488f04 = C0488f0.g;
                int i13 = z3 ? 1 : SubsamplingScaleImageView.TILE_SIZE_AUTO;
                P2 p2 = P2.a;
                i5 = 1;
                vA = B3.a(c0814p, 3);
                i6 = i13;
                c0488f02 = c0488f04;
            } else {
                c0814p.Q();
                z5 = z;
                l2 = l;
                c0488f02 = c0488f0;
                i6 = i;
                i5 = i2;
                vA = v;
            }
            c0814p.q();
            c0814p.X(30368324);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = androidx.compose.animation.d0.i(c0814p);
            }
            androidx.compose.foundation.interaction.l lVar = (androidx.compose.foundation.interaction.l) objI;
            c0814p.p(false);
            c0814p.X(30374434);
            long jC = l2.c();
            if (jC == 16) {
                jC = a4.c(z5, z2, ((Boolean) AbstractC3119d0.h(lVar, c0814p, 0).getValue()).booleanValue());
            }
            long j = jC;
            c0814p.p(false);
            androidx.compose.ui.text.L lE = l2.e(new androidx.compose.ui.text.L(j, 0L, null, null, null, 0L, 0, 0L, 16777214));
            androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
            boolean z6 = z5;
            c0814p = c0814p;
            C0776c.a(androidx.compose.foundation.text.selection.q0.a.a(a4.k), androidx.compose.runtime.internal.e.e(1830921872, new W2(qVar2, dVar4, bVar, z2, a4, a2, function12, z6, lE, c0490g0, c0488f02, z3, i6, i5, k, lVar, dVar5, dVar3, vA), c0814p), c0814p, 56);
            c0488f03 = c0488f02;
            i7 = i5;
            z4 = z6;
            v2 = vA;
            l3 = l2;
            i8 = i6;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new X2(a2, function1, qVar, z4, l3, dVar, dVar2, dVar3, z2, k, c0490g0, c0488f03, z3, i8, i7, v2, a4, i3);
        }
    }

    public static final void b(String str, Function1 function1, androidx.compose.ui.q qVar, boolean z, androidx.compose.ui.text.L l, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.camera.camera2.internal.s0 s0Var, C0490g0 c0490g0, C0488f0 c0488f0, boolean z2, int i, int i2, androidx.compose.ui.graphics.V v, A4 a4, InterfaceC0806l interfaceC0806l, int i3) {
        int i4;
        androidx.compose.ui.q qVar2;
        androidx.compose.runtime.internal.d dVar4;
        androidx.compose.runtime.internal.d dVar5;
        boolean z3;
        androidx.camera.camera2.internal.s0 s0Var2;
        C0490g0 c0490g02;
        C0488f0 c0488f02;
        int i5;
        int i6;
        boolean z4;
        C0490g0 c0490g03;
        C0488f0 c0488f03;
        int i7;
        int i8;
        androidx.camera.camera2.internal.s0 s0Var3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1922450045);
        if ((i3 & 6) == 0) {
            i4 = (c0814p.f(str) ? 4 : 2) | i3;
        } else {
            i4 = i3;
        }
        if ((i3 & 48) == 0) {
            i4 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i3 & 384) == 0) {
            qVar2 = qVar;
            i4 |= c0814p.f(qVar2) ? 256 : 128;
        } else {
            qVar2 = qVar;
        }
        int i9 = i4 | 27648;
        if ((196608 & i3) == 0) {
            i9 |= c0814p.f(l) ? 131072 : 65536;
        }
        int i10 = i9 | 1572864;
        if ((12582912 & i3) == 0) {
            dVar4 = dVar;
            i10 |= c0814p.h(dVar4) ? 8388608 : 4194304;
        } else {
            dVar4 = dVar;
        }
        if ((100663296 & i3) == 0) {
            dVar5 = dVar2;
            i10 |= c0814p.h(dVar5) ? 67108864 : 33554432;
        } else {
            dVar5 = dVar2;
        }
        if ((805306368 & i3) == 0) {
            i10 |= c0814p.h(dVar3) ? 536870912 : 268435456;
        }
        int i11 = (c0814p.f(v) ? ' ' : (char) 16) | 6 | (c0814p.f(a4) ? (char) 256 : (char) 128);
        if ((i10 & 306783379) == 306783378 && (i11 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            z4 = z;
            s0Var3 = s0Var;
            c0490g03 = c0490g0;
            c0488f03 = c0488f0;
            i7 = i;
            i8 = i2;
        } else {
            c0814p.S();
            if ((i3 & 1) == 0 || c0814p.w()) {
                androidx.camera.camera2.internal.s0 s0Var4 = androidx.compose.ui.text.input.J.a;
                z3 = true;
                s0Var2 = s0Var4;
                c0490g02 = C0490g0.e;
                c0488f02 = C0488f0.g;
                i5 = 1;
                i6 = z2 ? 1 : SubsamplingScaleImageView.TILE_SIZE_AUTO;
            } else {
                c0814p.Q();
                z3 = z;
                s0Var2 = s0Var;
                c0490g02 = c0490g0;
                c0488f02 = c0488f0;
                i6 = i;
                i5 = i2;
            }
            c0814p.q();
            c0814p.X(30062948);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = androidx.compose.animation.d0.i(c0814p);
            }
            androidx.compose.foundation.interaction.l lVar = (androidx.compose.foundation.interaction.l) objI;
            c0814p.p(false);
            c0814p.X(30069058);
            long jC = l.c();
            if (jC == 16) {
                jC = a4.c(z3, false, ((Boolean) AbstractC3119d0.h(lVar, c0814p, 0).getValue()).booleanValue());
            }
            long j = jC;
            c0814p.p(false);
            boolean z5 = z3;
            C0776c.a(androidx.compose.foundation.text.selection.q0.a.a(a4.k), androidx.compose.runtime.internal.e.e(-1886965181, new S2(qVar2, (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f), a4, str, function1, z5, l.e(new androidx.compose.ui.text.L(j, 0L, null, null, null, 0L, 0, 0L, 16777214)), c0490g02, c0488f02, z2, i6, i5, s0Var2, lVar, dVar4, dVar5, dVar3, v), c0814p), c0814p, 56);
            z4 = z5;
            c0490g03 = c0490g02;
            c0488f03 = c0488f02;
            i7 = i6;
            i8 = i5;
            s0Var3 = s0Var2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new T2(str, function1, qVar, z4, l, dVar, dVar2, dVar3, s0Var3, c0490g03, c0488f03, z2, i7, i8, v, a4, i3);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r15v3 */
    /* JADX WARN: Type inference failed for: r15v30 */
    /* JADX WARN: Type inference failed for: r15v4, types: [boolean, int] */
    public static final void c(Function2 function2, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, androidx.compose.runtime.internal.d dVar5, androidx.compose.runtime.internal.d dVar6, boolean z, float f, Function1 function1, androidx.compose.runtime.internal.d dVar7, androidx.compose.runtime.internal.d dVar8, androidx.compose.foundation.layout.A0 a0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        int i4;
        androidx.compose.foundation.layout.A0 a02;
        androidx.compose.ui.unit.k kVar;
        androidx.compose.runtime.internal.d dVar9;
        float f2;
        androidx.compose.runtime.internal.d dVar10;
        int i5;
        float f3;
        androidx.compose.runtime.internal.d dVar11;
        float f4;
        androidx.compose.runtime.internal.d dVar12;
        boolean z2;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1408290209);
        if ((i & 6) == 0) {
            i3 = i | (c0814p.f(nVar) ? 4 : 2);
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.h(function2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p.h(dVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p.h(dVar2) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p.h(dVar3) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p.h(dVar4) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i3 |= c0814p.h(dVar5) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i3 |= c0814p.h(dVar6) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i3 |= c0814p.g(z) ? 67108864 : 33554432;
        }
        if ((i & 805306368) == 0) {
            i3 |= c0814p.c(f) ? 536870912 : 268435456;
        }
        if ((i2 & 6) == 0) {
            i4 = i2 | (c0814p.h(function1) ? 4 : 2);
        } else {
            i4 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 |= c0814p.h(dVar7) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i4 |= c0814p.h(dVar8) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            a02 = a0;
            i4 |= c0814p.f(a02) ? 2048 : 1024;
        } else {
            a02 = a0;
        }
        int i6 = i4;
        if ((i3 & 306783379) == 306783378 && (i6 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            dVar11 = dVar2;
            dVar12 = dVar8;
            dVar9 = dVar5;
            f4 = f;
        } else {
            boolean z3 = ((i6 & 14) == 4) | ((i3 & 234881024) == 67108864) | ((i3 & 1879048192) == 536870912) | ((i6 & 7168) == 2048);
            Object objI = c0814p.I();
            if (z3 || objI == C0804k.a) {
                objI = new C0599c3(function1, z, f, a02);
                c0814p.i0(objI);
            }
            C0599c3 c0599c3 = (C0599c3) objI;
            androidx.compose.ui.unit.k kVar2 = (androidx.compose.ui.unit.k) c0814p.j(AbstractC0955m0.l);
            int i7 = c0814p.P;
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
            C0776c.E(c0814p, c0599c3, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            dVar7.invoke(c0814p, Integer.valueOf((i6 >> 3) & 14));
            c0814p.X(250370369);
            androidx.compose.ui.i iVar = androidx.compose.ui.b.e;
            if (dVar3 != null) {
                androidx.compose.ui.q qVarG = AbstractC0897s.k(nVar, "Leading").g(androidx.compose.material3.internal.Y.i);
                androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, false);
                int i8 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
                androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarG);
                c0814p.b0();
                kVar = kVar2;
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                    android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
                }
                C0776c.E(c0814p, qVarC2, c0912h4);
                androidx.compose.animation.d0.w((i3 >> 12) & 14, dVar3, c0814p, true);
            } else {
                kVar = kVar2;
            }
            ?? r15 = 0;
            c0814p.p(false);
            c0814p.X(250379492);
            if (dVar4 != null) {
                androidx.compose.ui.q qVarG2 = AbstractC0897s.k(nVar, "Trailing").g(androidx.compose.material3.internal.Y.i);
                androidx.compose.ui.layout.K kE2 = AbstractC0409s.e(iVar, false);
                int i9 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
                androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarG2);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE2, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i9))) {
                    android.support.v4.media.session.a.z(i9, c0814p, i9, c0912h3);
                }
                C0776c.E(c0814p, qVarC3, c0912h4);
                androidx.compose.animation.d0.w((i3 >> 15) & 14, dVar4, c0814p, true);
                r15 = 0;
            }
            c0814p.p(r15);
            androidx.compose.ui.unit.k kVar3 = kVar;
            float fK = AbstractC0382e.k(a02, kVar3);
            float fJ = AbstractC0382e.j(a02, kVar3);
            if (dVar3 != null) {
                fK -= androidx.compose.material3.internal.Y.c;
                float f5 = (float) r15;
                if (fK < f5) {
                    fK = f5;
                }
            }
            float f6 = fK;
            if (dVar4 != null) {
                fJ -= androidx.compose.material3.internal.Y.c;
                float f7 = 0;
                if (fJ < f7) {
                    fJ = f7;
                }
            }
            c0814p.X(250410106);
            androidx.compose.ui.i iVar2 = androidx.compose.ui.b.a;
            if (dVar5 != null) {
                f2 = fJ;
                androidx.compose.ui.q qVarY = AbstractC0382e.y(androidx.compose.foundation.layout.K0.r(androidx.compose.foundation.layout.K0.f(AbstractC0897s.k(nVar, "Prefix"), androidx.compose.material3.internal.Y.f, DefinitionKt.NO_Float_VALUE, 2), 3), f6, DefinitionKt.NO_Float_VALUE, androidx.compose.material3.internal.Y.e, DefinitionKt.NO_Float_VALUE, 10);
                androidx.compose.ui.layout.K kE3 = AbstractC0409s.e(iVar2, false);
                int i10 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L4 = c0814p.l();
                androidx.compose.ui.q qVarC4 = androidx.compose.ui.a.c(c0814p, qVarY);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE3, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L4, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i10))) {
                    android.support.v4.media.session.a.z(i10, c0814p, i10, c0912h3);
                }
                C0776c.E(c0814p, qVarC4, c0912h4);
                dVar9 = dVar5;
                androidx.compose.animation.d0.w((i3 >> 18) & 14, dVar9, c0814p, true);
            } else {
                dVar9 = dVar5;
                f2 = fJ;
            }
            c0814p.p(false);
            c0814p.X(250422072);
            if (dVar6 != null) {
                androidx.compose.ui.q qVarY2 = AbstractC0382e.y(androidx.compose.foundation.layout.K0.r(androidx.compose.foundation.layout.K0.f(AbstractC0897s.k(nVar, "Suffix"), androidx.compose.material3.internal.Y.f, DefinitionKt.NO_Float_VALUE, 2), 3), androidx.compose.material3.internal.Y.e, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, 10);
                androidx.compose.ui.layout.K kE4 = AbstractC0409s.e(iVar2, false);
                int i11 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L5 = c0814p.l();
                androidx.compose.ui.q qVarC5 = androidx.compose.ui.a.c(c0814p, qVarY2);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE4, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L5, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i11))) {
                    android.support.v4.media.session.a.z(i11, c0814p, i11, c0912h3);
                }
                C0776c.E(c0814p, qVarC5, c0912h4);
                dVar10 = dVar6;
                androidx.compose.animation.d0.w((i3 >> 21) & 14, dVar10, c0814p, true);
            } else {
                dVar10 = dVar6;
            }
            c0814p.p(false);
            float f8 = androidx.compose.material3.internal.Y.f;
            androidx.compose.ui.q qVarR = androidx.compose.foundation.layout.K0.r(androidx.compose.foundation.layout.K0.f(nVar, f8, DefinitionKt.NO_Float_VALUE, 2), 3);
            if (dVar9 == null) {
                f3 = f6;
                i5 = 0;
            } else {
                i5 = 0;
                f3 = 0;
            }
            androidx.compose.ui.q qVarY3 = AbstractC0382e.y(qVarR, f3, DefinitionKt.NO_Float_VALUE, dVar10 == null ? f2 : i5, DefinitionKt.NO_Float_VALUE, 10);
            c0814p.X(250444361);
            if (dVar != null) {
                dVar.invoke(AbstractC0897s.k(nVar, "Hint").g(qVarY3), c0814p, Integer.valueOf((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND));
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarG3 = AbstractC0897s.k(nVar, "TextField").g(qVarY3);
            androidx.compose.ui.layout.K kE5 = AbstractC0409s.e(iVar2, true);
            int i12 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L6 = c0814p.l();
            androidx.compose.ui.q qVarC6 = androidx.compose.ui.a.c(c0814p, qVarG3);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE5, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L6, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i12))) {
                android.support.v4.media.session.a.z(i12, c0814p, i12, c0912h3);
            }
            C0776c.E(c0814p, qVarC6, c0912h4);
            function2.invoke(c0814p, Integer.valueOf((i3 >> 3) & 14));
            c0814p.p(true);
            c0814p.X(250455481);
            if (dVar2 != null) {
                f4 = f;
                androidx.compose.ui.q qVarK = AbstractC0897s.k(androidx.compose.foundation.layout.K0.r(androidx.compose.foundation.layout.K0.f(nVar, V5.c(f8, androidx.compose.material3.internal.Y.g, f4), DefinitionKt.NO_Float_VALUE, 2), 3), "Label");
                androidx.compose.ui.layout.K kE6 = AbstractC0409s.e(iVar2, false);
                int i13 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L7 = c0814p.l();
                androidx.compose.ui.q qVarC7 = androidx.compose.ui.a.c(c0814p, qVarK);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE6, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L7, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i13))) {
                    android.support.v4.media.session.a.z(i13, c0814p, i13, c0912h3);
                }
                C0776c.E(c0814p, qVarC7, c0912h4);
                dVar11 = dVar2;
                androidx.compose.animation.d0.w((i3 >> 9) & 14, dVar11, c0814p, true);
            } else {
                dVar11 = dVar2;
                f4 = f;
            }
            c0814p.p(false);
            c0814p.X(250473414);
            if (dVar8 != null) {
                androidx.compose.ui.q qVarT = AbstractC0382e.t(androidx.compose.foundation.layout.K0.r(androidx.compose.foundation.layout.K0.f(AbstractC0897s.k(nVar, "Supporting"), androidx.compose.material3.internal.Y.h, DefinitionKt.NO_Float_VALUE, 2), 3), D4.d());
                androidx.compose.ui.layout.K kE7 = AbstractC0409s.e(iVar2, false);
                int i14 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L8 = c0814p.l();
                androidx.compose.ui.q qVarC8 = androidx.compose.ui.a.c(c0814p, qVarT);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE7, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L8, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i14))) {
                    android.support.v4.media.session.a.z(i14, c0814p, i14, c0912h3);
                }
                C0776c.E(c0814p, qVarC8, c0912h4);
                dVar12 = dVar8;
                z2 = true;
                androidx.compose.animation.d0.w((i6 >> 6) & 14, dVar12, c0814p, true);
            } else {
                dVar12 = dVar8;
                z2 = true;
            }
            c0814p.p(false);
            c0814p.p(z2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Y2(function2, dVar, dVar11, dVar3, dVar4, dVar9, dVar6, z, f4, function1, dVar7, dVar12, a02, i, i2);
        }
    }

    public static final int d(int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8, float f, long j, float f2, androidx.compose.foundation.layout.A0 a0) {
        int[] other = {i7, i3, i4, V5.d(i6, f, 0)};
        Intrinsics.checkNotNullParameter(other, "other");
        for (int i9 = 0; i9 < 4; i9++) {
            i5 = Math.max(i5, other[i9]);
        }
        float f3 = a0.b * f2;
        return Math.max(androidx.compose.ui.unit.a.i(j), Math.max(i, Math.max(i2, kotlin.math.c.b(V5.c(f3, Math.max(f3, i6 / 2.0f), f) + i5 + (a0.d * f2)))) + i8);
    }

    public static final int e(int i, int i2, int i3, int i4, int i5, int i6, int i7, float f, long j, float f2, androidx.compose.foundation.layout.A0 a0) {
        int i8 = i3 + i4;
        int iMax = Math.max(i5 + i8, Math.max(i7 + i8, V5.d(i6, f, 0))) + i + i2;
        androidx.compose.ui.unit.k kVar = androidx.compose.ui.unit.k.a;
        return Math.max(iMax, Math.max(kotlin.math.c.b((i6 + ((a0.c(kVar) + a0.b(kVar)) * f2)) * f), androidx.compose.ui.unit.a.j(j)));
    }

    public static final int f(boolean z, int i, int i2, androidx.compose.ui.layout.W w, androidx.compose.ui.layout.W w2) {
        if (z) {
            i2 = Math.round((1 + DefinitionKt.NO_Float_VALUE) * ((i - w2.b) / 2.0f));
        }
        float f = androidx.compose.material3.internal.Y.b;
        return Math.max(i2, (w != null ? w.b : 0) / 2);
    }
}
