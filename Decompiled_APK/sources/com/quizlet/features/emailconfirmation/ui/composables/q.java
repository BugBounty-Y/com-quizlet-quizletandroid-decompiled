package com.quizlet.features.emailconfirmation.ui.composables;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.gestures.C0346q0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C;
import androidx.compose.foundation.layout.C0384f;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.layout.G0;
import androidx.compose.foundation.layout.HorizontalAlignElement;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.graphics.U;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.D;
import androidx.compose.ui.text.L;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y4;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.assembly.compose.buttons.C4093s;
import com.quizlet.assembly.compose.buttons.C4094t;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class q {
    static {
        new r("user.email@email.com", s.a, false, "Resend confirmation", "Update email", 4);
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0049  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x005b  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0060  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00bf  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00ff  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x011d  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x019e  */
    /* JADX WARN: Removed duplicated region for block: B:84:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.quizlet.features.emailconfirmation.ui.composables.r r27, androidx.compose.ui.n r28, androidx.compose.material3.O3 r29, kotlin.jvm.functions.Function0 r30, kotlin.jvm.functions.Function0 r31, kotlin.jvm.functions.Function0 r32, long r33, androidx.compose.runtime.InterfaceC0806l r35, int r36, int r37) {
        /*
            Method dump skipped, instructions count: 426
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.emailconfirmation.ui.composables.q.a(com.quizlet.features.emailconfirmation.ui.composables.r, androidx.compose.ui.n, androidx.compose.material3.O3, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, long, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v2 */
    /* JADX WARN: Type inference failed for: r0v28 */
    /* JADX WARN: Type inference failed for: r0v3, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r4v1, types: [androidx.compose.runtime.l, androidx.compose.runtime.p] */
    /* JADX WARN: Type inference failed for: r8v28, types: [androidx.compose.ui.q] */
    public static final void b(r rVar, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function0 function03, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        C0912h c0912h;
        C0912h c0912h2;
        C0912h c0912h3;
        androidx.compose.ui.n nVar;
        ?? r0;
        C0912h c0912h4;
        float f;
        r rVar2;
        C0814p c0814p;
        InterfaceC0773a0 interfaceC0773a0;
        InterfaceC0773a0 interfaceC0773a02;
        androidx.constraintlayout.compose.i iVar;
        boolean z2;
        ?? r4 = (C0814p) interfaceC0806l;
        r4.Z(-2093417791);
        int i2 = i | (r4.f(rVar) ? 4 : 2) | (r4.f(qVar) ? 32 : 16) | (r4.h(function0) ? 256 : 128) | (r4.h(function02) ? 2048 : 1024) | (r4.h(function03) ? 16384 : 8192) | (r4.g(z) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && r4.x()) {
            r4.Q();
            c0814p = r4;
            rVar2 = rVar;
        } else {
            Object obj = C0804k.a;
            FillElement fillElement = K0.c;
            androidx.compose.ui.q qVarG = qVar.g(fillElement);
            C0384f c0384f = AbstractC0398m.c;
            androidx.compose.ui.g gVar = androidx.compose.ui.b.m;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0384f, gVar, r4, 0);
            int i3 = r4.P;
            InterfaceC0803j0 interfaceC0803j0L = r4.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(r4, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            r4.b0();
            if (r4.O) {
                r4.k(c0913i);
            } else {
                r4.l0();
            }
            C0912h c0912h5 = C0914j.f;
            C0776c.E(r4, bA, c0912h5);
            C0912h c0912h6 = C0914j.e;
            C0776c.E(r4, interfaceC0803j0L, c0912h6);
            C0912h c0912h7 = C0914j.g;
            if (r4.O || !Intrinsics.b(r4.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, r4, i3, c0912h7);
            }
            C0912h c0912h8 = C0914j.d;
            C0776c.E(r4, qVarC, c0912h8);
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(nVar2, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, 2);
            androidx.compose.ui.q qVarA = C.a(nVar2, 2.0f);
            K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i4 = r4.P;
            InterfaceC0803j0 interfaceC0803j0L2 = r4.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(r4, qVarA);
            r4.b0();
            if (r4.O) {
                r4.k(c0913i);
            } else {
                r4.l0();
            }
            C0776c.E(r4, kE, c0912h5);
            C0776c.E(r4, interfaceC0803j0L2, c0912h6);
            if (r4.O || !Intrinsics.b(r4.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, r4, i4, c0912h7);
            }
            C0776c.E(r4, qVarC2, c0912h8);
            r4.X(2075396468);
            if (z) {
                androidx.compose.ui.q qVarG2 = N.G(fillElement, "graphic");
                r4.X(-1003410150);
                r4.X(212064437);
                r4.p(false);
                androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) r4.j(AbstractC0955m0.f);
                Object objI = r4.I();
                if (objI == obj) {
                    objI = new androidx.constraintlayout.compose.j(bVar);
                    r4.i0(objI);
                }
                androidx.constraintlayout.compose.j jVar = (androidx.constraintlayout.compose.j) objI;
                Object objI2 = r4.I();
                if (objI2 == obj) {
                    objI2 = new androidx.constraintlayout.compose.g();
                    r4.i0(objI2);
                }
                androidx.constraintlayout.compose.g gVar2 = (androidx.constraintlayout.compose.g) objI2;
                Object objI3 = r4.I();
                if (objI3 == obj) {
                    objI3 = C0776c.z(Boolean.FALSE);
                    r4.i0(objI3);
                }
                InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) objI3;
                Object objI4 = r4.I();
                if (objI4 == obj) {
                    objI4 = new androidx.constraintlayout.compose.i(gVar2);
                    r4.i0(objI4);
                }
                androidx.constraintlayout.compose.i iVar2 = (androidx.constraintlayout.compose.i) objI4;
                Object objI5 = r4.I();
                if (objI5 == obj) {
                    objI5 = C0776c.y(Unit.a, V.c);
                    r4.i0(objI5);
                }
                InterfaceC0773a0 interfaceC0773a04 = (InterfaceC0773a0) objI5;
                boolean zH = r4.h(jVar) | r4.d(257);
                Object objI6 = r4.I();
                if (zH || objI6 == obj) {
                    c0912h2 = c0912h8;
                    objI6 = new k(interfaceC0773a04, jVar, iVar2, interfaceC0773a03, 0);
                    interfaceC0773a0 = interfaceC0773a04;
                    interfaceC0773a02 = interfaceC0773a03;
                    nVar = nVar2;
                    iVar = iVar2;
                    r4.i0(objI6);
                } else {
                    c0912h2 = c0912h8;
                    nVar = nVar2;
                    interfaceC0773a0 = interfaceC0773a04;
                    iVar = iVar2;
                    interfaceC0773a02 = interfaceC0773a03;
                }
                K k = (K) objI6;
                c0912h3 = c0912h7;
                Object objI7 = r4.I();
                if (objI7 == obj) {
                    c0912h = c0912h6;
                    objI7 = new l(interfaceC0773a02, iVar, 0);
                    r4.i0(objI7);
                } else {
                    c0912h = c0912h6;
                }
                Function0 function04 = (Function0) objI7;
                boolean zH2 = r4.h(jVar);
                Object objI8 = r4.I();
                if (zH2 || objI8 == obj) {
                    z2 = false;
                    objI8 = new m(jVar, 0);
                    r4.i0(objI8);
                } else {
                    z2 = false;
                }
                AbstractC0897s.a(androidx.compose.ui.semantics.m.a(qVarG2, z2, (Function1) objI8), androidx.compose.runtime.internal.e.e(1200550679, new C0346q0(interfaceC0773a0, gVar2, function04, 10), r4), k, r4, 48);
                r4.p(z2);
                r0 = z2;
            } else {
                c0912h = c0912h6;
                c0912h2 = c0912h8;
                c0912h3 = c0912h7;
                nVar = nVar2;
                r0 = 0;
            }
            r4.p(r0);
            androidx.compose.ui.q qVarU = AbstractC0460p.u(fillElement, AbstractC0460p.r(r4), r0, 14);
            androidx.compose.foundation.layout.B bA2 = androidx.compose.foundation.layout.A.a(c0384f, gVar, r4, r0);
            int i5 = r4.P;
            InterfaceC0803j0 interfaceC0803j0L3 = r4.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(r4, qVarU);
            r4.b0();
            if (r4.O) {
                r4.k(c0913i);
            } else {
                r4.l0();
            }
            C0776c.E(r4, bA2, c0912h5);
            C0912h c0912h9 = c0912h;
            C0776c.E(r4, interfaceC0803j0L3, c0912h9);
            if (r4.O || !Intrinsics.b(r4.I(), Integer.valueOf(i5))) {
                c0912h4 = c0912h3;
                android.support.v4.media.session.a.z(i5, r4, i5, c0912h4);
            } else {
                c0912h4 = c0912h3;
            }
            C0912h c0912h10 = c0912h2;
            C0776c.E(r4, qVarC3, c0912h10);
            androidx.compose.ui.n nVar3 = nVar;
            androidx.compose.ui.q qVarC4 = K0.c(nVar3, 1.0f);
            if (z) {
                mVar.v();
                f = com.quizlet.ui.resources.designsystem.generated.j.l;
            } else {
                mVar.p();
                f = com.quizlet.ui.resources.designsystem.generated.j.j;
            }
            androidx.compose.ui.q qVarG3 = AbstractC0382e.y(qVarC4, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13).g(qVarW);
            String strI = i(rVar, r4);
            androidx.compose.runtime.B b = com.quizlet.themes.w.b;
            L l = ((com.quizlet.themes.f) r4.j(b)).e;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            C0912h c0912h11 = c0912h4;
            rVar2 = rVar;
            Q4.b(strI, qVarG3, ((com.quizlet.themes.b) r4.j(b2)).b.e(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, r4, 0, 0, 65016);
            androidx.compose.ui.q qVarC5 = K0.c(nVar3, 1.0f);
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            Q4.c(h(rVar2, r4), AbstractC0382e.y(qVarC5, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13).g(qVarW), ((com.quizlet.themes.b) r4.j(b2)).b.e(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, null, ((com.quizlet.themes.f) r4.j(b)).o, r4, 0, 0, 130552);
            androidx.compose.ui.q qVarC6 = K0.c(nVar3, 1.0f);
            mVar.s();
            Q4.b(f(rVar2, r4), AbstractC0382e.y(qVarC6, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13).g(qVarW), g(rVar2, r4), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) r4.j(b)).q, r4, 0, 0, 65016);
            r4.p(true);
            r4.p(true);
            r4.X(-1875778441);
            androidx.compose.ui.n nVarF = z ? AbstractC0460p.f(nVar3, ((com.quizlet.themes.b) r4.j(b2)).A0, F.a) : nVar3;
            r4.p(false);
            mVar.s();
            androidx.compose.ui.q qVarG4 = AbstractC0382e.y(nVarF, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f2, 7).g(qVarW);
            androidx.compose.foundation.layout.B bA3 = androidx.compose.foundation.layout.A.a(c0384f, gVar, r4, 0);
            int i6 = r4.P;
            InterfaceC0803j0 interfaceC0803j0L4 = r4.l();
            androidx.compose.ui.q qVarC7 = androidx.compose.ui.a.c(r4, qVarG4);
            r4.b0();
            if (r4.O) {
                r4.k(c0913i);
            } else {
                r4.l0();
            }
            C0776c.E(r4, bA3, c0912h5);
            C0776c.E(r4, interfaceC0803j0L4, c0912h9);
            if (r4.O || !Intrinsics.b(r4.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, r4, i6, c0912h11);
            }
            C0776c.E(r4, qVarC7, c0912h10);
            W4.a(rVar2.d, K0.c(nVar3, 1.0f), function0, !rVar2.c, null, null, null, null, null, false, r4, (i2 & 896) | 48, 1008);
            C0814p c0814p2 = r4;
            c0814p2.X(2075556019);
            String str = rVar2.e;
            if (str != null) {
                androidx.compose.ui.q qVarC8 = K0.c(nVar3, 1.0f);
                mVar.s();
                Y4.b(str, AbstractC0382e.y(qVarC8, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function02, false, null, null, ((com.quizlet.themes.b) c0814p2.j(b2)).b.g(), 0L, null, null, null, c0814p2, (i2 >> 3) & 896, 0, 3960);
                c0814p2 = c0814p2;
                Unit unit = Unit.a;
            }
            c0814p2.p(false);
            c0814p2.X(2075570306);
            C0814p c0814p3 = c0814p2;
            String str2 = rVar2.f;
            if (str2 == null) {
                c0814p = c0814p3;
            } else {
                androidx.compose.ui.q qVarC9 = K0.c(nVar3, 1.0f);
                mVar.u();
                AbstractC3586b5.a(str2, AbstractC0382e.y(qVarC9, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function03, false, null, null, null, null, null, c0814p3, (i2 >> 6) & 896, 1016);
                c0814p = c0814p3;
                Unit unit2 = Unit.a;
            }
            androidx.compose.ui.node.B.s(c0814p, false, true, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new e(rVar2, qVar, function0, function02, function03, z, i);
        }
    }

    public static final void c(r rVar, androidx.compose.ui.q qVar, float f, Function0 function0, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar;
        InterfaceC0773a0 interfaceC0773a0;
        androidx.constraintlayout.compose.j jVar;
        InterfaceC0773a0 interfaceC0773a02;
        C0912h c0912h;
        androidx.constraintlayout.compose.i iVar;
        float f2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(822013798);
        int i2 = i | (c0814p.f(rVar) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.c(f) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024) | (c0814p.h(function02) ? 16384 : 8192) | (c0814p.h(function03) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object obj = C0804k.a;
            FillElement fillElement = K0.c;
            androidx.compose.ui.q qVarG = qVar.g(fillElement);
            K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            Function0 function04 = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(function04);
            } else {
                c0814p.l0();
            }
            C0912h c0912h2 = C0914j.f;
            C0776c.E(c0814p, kE, c0912h2);
            C0912h c0912h3 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h3);
            C0912h c0912h4 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h4);
            }
            C0912h c0912h5 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h5);
            C0418x c0418x = C0418x.a;
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarA = c0418x.a(nVar2, androidx.compose.ui.b.f);
            c0814p.X(-1003410150);
            c0814p.X(212064437);
            c0814p.p(false);
            androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
            Object objI = c0814p.I();
            if (objI == obj) {
                objI = new androidx.constraintlayout.compose.j(bVar);
                c0814p.i0(objI);
            }
            androidx.constraintlayout.compose.j jVar2 = (androidx.constraintlayout.compose.j) objI;
            Object objI2 = c0814p.I();
            if (objI2 == obj) {
                objI2 = new androidx.constraintlayout.compose.g();
                c0814p.i0(objI2);
            }
            androidx.constraintlayout.compose.g gVar = (androidx.constraintlayout.compose.g) objI2;
            Object objI3 = c0814p.I();
            if (objI3 == obj) {
                objI3 = C0776c.z(Boolean.FALSE);
                c0814p.i0(objI3);
            }
            InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) objI3;
            Object objI4 = c0814p.I();
            if (objI4 == obj) {
                objI4 = new androidx.constraintlayout.compose.i(gVar);
                c0814p.i0(objI4);
            }
            androidx.constraintlayout.compose.i iVar2 = (androidx.constraintlayout.compose.i) objI4;
            Object objI5 = c0814p.I();
            if (objI5 == obj) {
                nVar = nVar2;
                objI5 = C0776c.y(Unit.a, V.c);
                c0814p.i0(objI5);
            } else {
                nVar = nVar2;
            }
            InterfaceC0773a0 interfaceC0773a04 = (InterfaceC0773a0) objI5;
            boolean zD = c0814p.d(257) | c0814p.h(jVar2);
            Object objI6 = c0814p.I();
            if (zD || objI6 == obj) {
                interfaceC0773a0 = interfaceC0773a04;
                objI6 = new k(interfaceC0773a0, jVar2, iVar2, interfaceC0773a03, 1);
                jVar = jVar2;
                interfaceC0773a02 = interfaceC0773a03;
                c0912h = c0912h3;
                iVar = iVar2;
                c0814p.i0(objI6);
            } else {
                interfaceC0773a0 = interfaceC0773a04;
                c0912h = c0912h3;
                jVar = jVar2;
                iVar = iVar2;
                interfaceC0773a02 = interfaceC0773a03;
            }
            K k = (K) objI6;
            Object objI7 = c0814p.I();
            if (objI7 == obj) {
                objI7 = new l(interfaceC0773a02, iVar, 1);
                c0814p.i0(objI7);
            }
            Function0 function05 = (Function0) objI7;
            boolean zH = c0814p.h(jVar);
            Object objI8 = c0814p.I();
            if (zH || objI8 == obj) {
                objI8 = new m(jVar, 1);
                c0814p.i0(objI8);
            }
            C0912h c0912h6 = c0912h;
            androidx.compose.ui.n nVar3 = nVar;
            AbstractC0897s.a(androidx.compose.ui.semantics.m.a(qVarA, false, (Function1) objI8), androidx.compose.runtime.internal.e.e(1200550679, new p(interfaceC0773a0, gVar, function05, f, 0), c0814p), k, c0814p, 48);
            c0814p.p(false);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, fillElement);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(function04);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h2);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h6);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h4);
            }
            C0776c.E(c0814p, qVarC2, c0912h5);
            String str = rVar.f;
            c0814p.X(385493186);
            if (str != null) {
                HorizontalAlignElement horizontalAlignElement = new HorizontalAlignElement(androidx.compose.ui.b.o);
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.p();
                float f3 = com.quizlet.ui.resources.designsystem.generated.j.j;
                mVar.p();
                Y4.b(str, AbstractC0382e.y(horizontalAlignElement, DefinitionKt.NO_Float_VALUE, f3, f3, DefinitionKt.NO_Float_VALUE, 9), function03, false, null, null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), 0L, C4093s.a, null, null, c0814p, (i2 >> 9) & 896, 0, 3448);
                Unit unit = Unit.a;
            }
            c0814p.p(false);
            if (rVar.f != null) {
                com.quizlet.themes.m.g.u();
                f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
            } else {
                f2 = 88;
            }
            int i5 = i2 >> 3;
            e(rVar, AbstractC0382e.w(AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 88, DefinitionKt.NO_Float_VALUE, 2), function0, function02, c0814p, (i2 & 14) | (i5 & 896) | (i5 & 7168));
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new d(rVar, qVar, f, function0, function02, function03, i, 1);
        }
    }

    public static final void d(r rVar, androidx.compose.ui.q qVar, float f, Function0 function0, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i) {
        androidx.constraintlayout.compose.i iVar;
        InterfaceC0773a0 interfaceC0773a0;
        C0912h c0912h;
        float f2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1345722210);
        int i2 = i | (c0814p.f(rVar) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.c(f) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024) | (c0814p.h(function02) ? 16384 : 8192) | (c0814p.h(function03) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object obj = C0804k.a;
            FillElement fillElement = K0.c;
            androidx.compose.ui.q qVarG = qVar.g(fillElement);
            K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            Function0 function04 = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(function04);
            } else {
                c0814p.l0();
            }
            C0912h c0912h2 = C0914j.f;
            C0776c.E(c0814p, kE, c0912h2);
            C0912h c0912h3 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h3);
            C0912h c0912h4 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h4);
            }
            C0912h c0912h5 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h5);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p.X(-1003410150);
            c0814p.X(212064437);
            c0814p.p(false);
            androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
            Object objI = c0814p.I();
            if (objI == obj) {
                objI = new androidx.constraintlayout.compose.j(bVar);
                c0814p.i0(objI);
            }
            androidx.constraintlayout.compose.j jVar = (androidx.constraintlayout.compose.j) objI;
            Object objI2 = c0814p.I();
            if (objI2 == obj) {
                objI2 = new androidx.constraintlayout.compose.g();
                c0814p.i0(objI2);
            }
            androidx.constraintlayout.compose.g gVar = (androidx.constraintlayout.compose.g) objI2;
            Object objI3 = c0814p.I();
            if (objI3 == obj) {
                objI3 = C0776c.z(Boolean.FALSE);
                c0814p.i0(objI3);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI3;
            Object objI4 = c0814p.I();
            if (objI4 == obj) {
                objI4 = new androidx.constraintlayout.compose.i(gVar);
                c0814p.i0(objI4);
            }
            androidx.constraintlayout.compose.i iVar2 = (androidx.constraintlayout.compose.i) objI4;
            Object objI5 = c0814p.I();
            if (objI5 == obj) {
                objI5 = C0776c.y(Unit.a, V.c);
                c0814p.i0(objI5);
            }
            InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) objI5;
            boolean zH = c0814p.h(jVar) | c0814p.d(257);
            Object objI6 = c0814p.I();
            if (zH || objI6 == obj) {
                objI6 = new k(interfaceC0773a03, jVar, iVar2, interfaceC0773a02, 2);
                iVar = iVar2;
                interfaceC0773a0 = interfaceC0773a02;
                c0814p.i0(objI6);
            } else {
                iVar = iVar2;
                interfaceC0773a0 = interfaceC0773a02;
            }
            K k = (K) objI6;
            Object objI7 = c0814p.I();
            if (objI7 == obj) {
                c0912h = c0912h3;
                objI7 = new l(interfaceC0773a0, iVar, 2);
                c0814p.i0(objI7);
            } else {
                c0912h = c0912h3;
            }
            Function0 function05 = (Function0) objI7;
            boolean zH2 = c0814p.h(jVar);
            Object objI8 = c0814p.I();
            if (zH2 || objI8 == obj) {
                objI8 = new m(jVar, 2);
                c0814p.i0(objI8);
            }
            C0912h c0912h6 = c0912h;
            AbstractC0897s.a(androidx.compose.ui.semantics.m.a(fillElement, false, (Function1) objI8), androidx.compose.runtime.internal.e.e(1200550679, new p(interfaceC0773a03, gVar, function05, f, 1), c0814p), k, c0814p, 48);
            c0814p.p(false);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, fillElement);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(function04);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h2);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h6);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h4);
            }
            C0776c.E(c0814p, qVarC2, c0912h5);
            String str = rVar.f;
            c0814p.X(1787005501);
            if (str != null) {
                HorizontalAlignElement horizontalAlignElement = new HorizontalAlignElement(androidx.compose.ui.b.o);
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.q();
                float f3 = com.quizlet.ui.resources.designsystem.generated.j.i;
                mVar.q();
                Y4.b(str, AbstractC0382e.y(horizontalAlignElement, DefinitionKt.NO_Float_VALUE, f3, f3, DefinitionKt.NO_Float_VALUE, 9), function03, false, null, null, 0L, 0L, C4094t.a, null, null, c0814p, (i2 >> 9) & 896, 0, 3576);
                Unit unit = Unit.a;
            }
            c0814p.p(false);
            if (rVar.f != null) {
                com.quizlet.themes.m.g.u();
                f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
            } else {
                f2 = 80;
            }
            androidx.compose.ui.q qVarW = AbstractC0382e.w(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 72, DefinitionKt.NO_Float_VALUE, 2);
            int i5 = i2 >> 3;
            e(rVar, qVarW, function0, function02, c0814p, (i2 & 14) | (i5 & 896) | (i5 & 7168));
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new d(rVar, qVar, f, function0, function02, function03, i, 0);
        }
    }

    public static final void e(r rVar, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function0 function03;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-859826373);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(rVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            function03 = function02;
            i2 |= c0814p.h(function03) ? 2048 : 1024;
        } else {
            function03 = function02;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarQ = K0.q(qVar, DefinitionKt.NO_Float_VALUE, com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR, 1);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarQ);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            String strI = i(rVar, c0814p);
            androidx.compose.runtime.B b = com.quizlet.themes.w.b;
            L l = ((com.quizlet.themes.f) c0814p.j(b)).c;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            Q4.b(strI, null, ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65530);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            Q4.c(h(rVar, c0814p), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, null, ((com.quizlet.themes.f) c0814p.j(b)).m, c0814p, 0, 0, 131064);
            mVar.s();
            Q4.b(f(rVar, c0814p), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), g(rVar, c0814p), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).o, c0814p, 0, 0, 65528);
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, 40, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            G0 g0B = E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarY);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            W4.a(rVar.d, null, function0, !rVar.c, null, null, null, null, null, false, c0814p, i2 & 896, 1010);
            c0814p = c0814p;
            c0814p.X(-438606415);
            String str = rVar.e;
            if (str != null) {
                mVar.u();
                AbstractC3586b5.a(str, AbstractC0382e.y(nVar, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), function03, false, null, null, null, null, null, c0814p, (i2 >> 3) & 896, 1016);
                Unit unit = Unit.a;
            }
            androidx.compose.ui.node.B.s(c0814p, false, true, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i(rVar, qVar, function0, function02, i, 4);
        }
    }

    public static final String f(r rVar, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(489875666);
        String strH = rVar.c ? Z.h(c0814p, -1211254806, R.string.request_limit_reached_error, c0814p, false) : Z.h(c0814p, -1211184653, R.string.confirm_email_info, c0814p, false);
        c0814p.p(false);
        return strH;
    }

    public static final long g(r rVar, InterfaceC0806l interfaceC0806l) {
        long jE;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1635074580);
        if (rVar.c) {
            c0814p.X(1075811642);
            jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.a();
            c0814p.p(false);
        } else {
            c0814p.X(1075858452);
            jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
            c0814p.p(false);
        }
        c0814p.p(false);
        return jE;
    }

    public static final C0995g h(r rVar, InterfaceC0806l interfaceC0806l) {
        int i;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1424895277);
        C0984d c0984d = new C0984d();
        int iOrdinal = rVar.b.ordinal();
        if (iOrdinal == 0) {
            i = R.string.confirm_email_message;
        } else {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            i = R.string.underage_confirm_email_message;
        }
        String str = rVar.a;
        String strC = AbstractC3106b5.c(i, new Object[]{str}, c0814p);
        int iM = StringsKt.M(strC, str, 0, false, 6);
        c0984d.f(strC);
        c0984d.c(new D(0L, 0L, androidx.compose.ui.text.font.u.i, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, (androidx.compose.ui.text.font.j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (U) null, 65531), iM, str.length() + iM);
        C0995g c0995gJ = c0984d.j();
        c0814p.p(false);
        return c0995gJ;
    }

    public static final String i(r rVar, InterfaceC0806l interfaceC0806l) {
        String strH;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-17517228);
        int iOrdinal = rVar.b.ordinal();
        if (iOrdinal == 0) {
            strH = Z.h(c0814p, -188992416, R.string.confirm_email_title, c0814p, false);
        } else {
            if (iOrdinal != 1) {
                throw Z.j(-188994112, c0814p, false);
            }
            strH = Z.h(c0814p, -188989495, R.string.underage_confirm_email_title, c0814p, false);
        }
        c0814p.p(false);
        return strH;
    }
}
