package com.quizlet.features.questiontypes.fitb.ui;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.G0;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import androidx.lifecycle.B;
import androidx.lifecycle.C0;
import androidx.lifecycle.InterfaceC1261w;
import androidx.lifecycle.J;
import androidx.lifecycle.w0;
import androidx.navigation.compose.C1278k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_camera.H2;
import com.google.android.gms.internal.mlkit_vision_camera.K2;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4392k;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.N;
import com.quizlet.features.questiontypes.fitb.m;
import com.quizlet.features.questiontypes.fitb.n;
import com.quizlet.features.questiontypes.fitb.o;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import com.quizlet.themes.w;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.W;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public abstract class l {
    /* JADX WARN: Removed duplicated region for block: B:38:0x0180  */
    /* JADX WARN: Removed duplicated region for block: B:47:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(kotlinx.collections.immutable.b r29, androidx.compose.animation.core.J0 r30, kotlin.jvm.functions.Function1 r31, kotlin.jvm.functions.Function1 r32, androidx.compose.runtime.InterfaceC0806l r33, int r34) {
        /*
            Method dump skipped, instructions count: 404
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.fitb.ui.l.a(kotlinx.collections.immutable.b, androidx.compose.animation.core.J0, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int):void");
    }

    public static final void b(com.quizlet.features.questiontypes.fitb.g gVar, W w, q qVar, Function0 function0, Function1 function1, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(791973789);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(gVar) : c0814p2.h(gVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(w) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(function0) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(function1) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.h(function02) ? 131072 : 65536;
        }
        int i3 = i2;
        if ((74899 & i3) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            V v = C0804k.a;
            c0814p2.X(-1562501825);
            Object objI = c0814p2.I();
            if (objI == v) {
                c0814p2.i0(function02);
                objI = function02;
            }
            Function0 function03 = (Function0) objI;
            Object objG = Z.g(-1562500281, c0814p2, false);
            if (objG == v) {
                objG = C0776c.z(Boolean.FALSE);
                c0814p2.i0(objG);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objG;
            c0814p2.p(false);
            com.quizlet.features.questiontypes.basequestion.data.a aVar = gVar.d;
            c0814p2.X(-1562497740);
            boolean zH = c0814p2.h(gVar);
            Object objI2 = c0814p2.I();
            if (zH || objI2 == v) {
                objI2 = new j(gVar, function03, interfaceC0773a0, null);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            C0776c.f(c0814p2, aVar, (Function2) objI2);
            x xVarH = Y5.h(true, false, c0814p2, 6, 6);
            c0814p2.X(-1562488597);
            boolean zH2 = c0814p2.h(xVarH);
            Object objI3 = c0814p2.I();
            if (zH2 || objI3 == v) {
                objI3 = new k(xVarH, null);
                c0814p2.i0(objI3);
            }
            c0814p2.p(false);
            c0814p2.X(-827048655);
            J j = (J) c0814p2.j(androidx.lifecycle.compose.g.a);
            B b = B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI3, c0814p2);
            Unit unit = Unit.a;
            c0814p2.X(1667431386);
            boolean zH3 = c0814p2.h(j) | c0814p2.h(w) | c0814p2.f(b) | c0814p2.f(interfaceC0773a0D);
            Object objI4 = c0814p2.I();
            if (zH3 || objI4 == v) {
                objI4 = new i(interfaceC0773a0D, j, null, w);
                c0814p2.i0(objI4);
            }
            c0814p2.p(false);
            C0776c.f(c0814p2, unit, (Function2) objI4);
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(qVar, null, androidx.compose.runtime.internal.e.e(-1416805448, new com.quizlet.assembly.compose.menu.l(xVarH, interfaceC0773a0, gVar, 20), c0814p2), null, null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(-949200722, new com.quizlet.assembly.compose.input.h(14, gVar, function1, function0, false), c0814p2), c0814p, ((i3 >> 6) & 14) | 805306752, 506);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.screens.a(gVar, w, qVar, function0, function1, function02, i);
        }
    }

    public static final void c(com.quizlet.features.questiontypes.basequestion.i questionViewModel, q qVar, m mVar, InterfaceC0806l interfaceC0806l, int i) {
        final m mVar2;
        int i2;
        m mVar3;
        Intrinsics.checkNotNullParameter(questionViewModel, "questionViewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1428084239);
        int i3 = i | (c0814p.f(questionViewModel) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | 128;
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            mVar3 = mVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                w0 w0VarE = AbstractC3417z1.e(m.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                mVar2 = (m) w0VarE;
                i2 = i3 & (-897);
            } else {
                c0814p.Q();
                i2 = i3 & (-897);
                mVar2 = mVar;
            }
            c0814p.q();
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(mVar2.i, c0814p);
            int i4 = i2 << 3;
            K2.a(mVar2.m, questionViewModel, c0814p, i4 & ContentType.LONG_FORM_ON_DEMAND);
            com.quizlet.features.questiontypes.fitb.g gVar = (com.quizlet.features.questiontypes.fitb.g) interfaceC0773a0M.getValue();
            d0 d0Var = mVar2.k;
            c0814p.X(-276213345);
            boolean zH = c0814p.h(mVar2);
            Object objI = c0814p.I();
            V v = C0804k.a;
            if (zH || objI == v) {
                final int i5 = 0;
                objI = new Function0() { // from class: com.quizlet.features.questiontypes.fitb.ui.g
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i5) {
                            case 0:
                                mVar2.A(o.a);
                                break;
                            default:
                                mVar2.A(n.a);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(objI);
            }
            Function0 function0 = (Function0) objI;
            c0814p.p(false);
            c0814p.X(-276211034);
            boolean zH2 = c0814p.h(mVar2);
            Object objI2 = c0814p.I();
            if (zH2 || objI2 == v) {
                objI2 = new com.quizlet.features.folders.composables.J(mVar2, 10);
                c0814p.i0(objI2);
            }
            Function1 function1 = (Function1) objI2;
            c0814p.p(false);
            c0814p.X(-276208511);
            boolean zH3 = c0814p.h(mVar2);
            Object objI3 = c0814p.I();
            if (zH3 || objI3 == v) {
                final int i6 = 1;
                objI3 = new Function0() { // from class: com.quizlet.features.questiontypes.fitb.ui.g
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i6) {
                            case 0:
                                mVar2.A(o.a);
                                break;
                            default:
                                mVar2.A(n.a);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            b(gVar, d0Var, qVar, function0, function1, (Function0) objI3, c0814p, i4 & 896);
            mVar3 = mVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new N(i, 5, qVar, (Object) questionViewModel, (Object) mVar3);
        }
    }

    public static final void d(N2 n2, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-653659668);
        if ((((c0814p.f(n2) ? 32 : 16) | i) & 17) == 16 && c0814p.x()) {
            c0814p.Q();
        } else {
            Q4.b(AbstractC3106b5.d(c0814p, R.string.fitb_prompt_label), null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(w.a)).k, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            q qVarC = K0.c(androidx.compose.ui.n.b, 1.0f);
            com.quizlet.themes.m.g.m();
            q qVarG = androidx.compose.ui.platform.N.G(AbstractC0382e.y(qVarC, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.n, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "promptView");
            com.quizlet.features.questiontypes.data.d dVar = n2 instanceof com.quizlet.features.questiontypes.data.d ? (com.quizlet.features.questiontypes.data.d) n2 : null;
            com.quizlet.features.questiontypes.data.b bVar = n2 instanceof com.quizlet.features.questiontypes.data.b ? (com.quizlet.features.questiontypes.data.b) n2 : null;
            DiagramData diagramData = bVar != null ? bVar.a : null;
            c0814p.X(-979430890);
            Object objI = c0814p.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = new C4392k(19);
                c0814p.i0(objI);
            }
            Function0 function0 = (Function0) objI;
            Object objG = Z.g(-979429601, c0814p, false);
            if (objG == v) {
                objG = new C4392k(20);
                c0814p.i0(objG);
            }
            Function0 function02 = (Function0) objG;
            Object objG2 = Z.g(-979426998, c0814p, false);
            if (objG2 == v) {
                objG2 = new C4392k(21);
                c0814p.i0(objG2);
            }
            c0814p.p(false);
            H2.a(dVar, diagramData, qVarG, DefinitionKt.NO_Float_VALUE, function0, function02, (Function0) objG2, c0814p, 1794048);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(n2, i, 17);
        }
    }

    public static final void e(int i, InterfaceC0806l interfaceC0806l, Function0 function0, Function0 function02, boolean z) {
        Function0 function03;
        C0814p c0814p;
        boolean z2;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-118158988);
        int i2 = (c0814p2.g(z) ? 32 : 16) | i | (c0814p2.h(function0) ? 256 : 128) | (c0814p2.h(function02) ? 2048 : 1024);
        if ((i2 & 1169) == 1168 && c0814p2.x()) {
            c0814p2.Q();
            function03 = function02;
            c0814p = c0814p2;
            z2 = z;
        } else {
            q qVarC = K0.c(androidx.compose.ui.n.b, 1.0f);
            com.quizlet.themes.m.g.s();
            q qVarY = AbstractC0382e.y(qVarC, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, 7);
            G0 g0B = E0.b(AbstractC0398m.b, androidx.compose.ui.b.j, c0814p2, 6);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarY);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, g0B, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h);
            }
            C0776c.E(c0814p2, qVarC2, C0914j.d);
            if (z) {
                c0814p2.X(1758556031);
                W4.a(AbstractC3106b5.d(c0814p2, R.string.submit_answer_button), null, function02, false, null, null, null, null, null, false, c0814p2, (i2 >> 3) & 896, 1018);
                function03 = function02;
                c0814p2.p(false);
                c0814p = c0814p2;
                z2 = z;
            } else {
                function03 = function02;
                c0814p2.X(1758731863);
                c0814p = c0814p2;
                z2 = z;
                AbstractC3586b5.a(AbstractC3106b5.d(c0814p2, R.string.written_question_do_not_know), null, function0, false, null, null, null, null, null, c0814p, i2 & 896, 1018);
                c0814p.p(false);
            }
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.upload.e(z2, function0, function03, i);
        }
    }
}
