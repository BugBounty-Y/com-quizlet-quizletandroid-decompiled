package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.layout.InterfaceC0388h;
import androidx.compose.foundation.layout.InterfaceC0394k;
import androidx.compose.foundation.lazy.grid.C0426a;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3155h0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.b5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3586b5 {
    /* JADX WARN: Removed duplicated region for block: B:100:0x012e  */
    /* JADX WARN: Removed duplicated region for block: B:101:0x0131  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0135  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x0139  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x013f  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0144  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x0148  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x018d  */
    /* JADX WARN: Removed duplicated region for block: B:119:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x004a  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0059  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x005f  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x009e A[PHI: r15
  0x009e: PHI (r15v21 int) = (r15v0 int), (r15v6 int), (r15v7 int) binds: [B:54:0x009c, B:64:0x00b6, B:63:0x00b3] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00c4  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x010e  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x0125  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x012a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(java.lang.String r18, androidx.compose.ui.q r19, kotlin.jvm.functions.Function0 r20, boolean r21, com.quizlet.assembly.compose.buttons.O r22, com.quizlet.assembly.compose.buttons.InterfaceC4099y r23, com.quizlet.assembly.compose.buttons.C4076a r24, com.quizlet.assembly.compose.buttons.InterfaceC4092q r25, androidx.compose.ui.graphics.painter.b r26, androidx.compose.runtime.InterfaceC0806l r27, int r28, int r29) {
        /*
            Method dump skipped, instructions count: 413
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5.a(java.lang.String, androidx.compose.ui.q, kotlin.jvm.functions.Function0, boolean, com.quizlet.assembly.compose.buttons.O, com.quizlet.assembly.compose.buttons.y, com.quizlet.assembly.compose.buttons.a, com.quizlet.assembly.compose.buttons.q, androidx.compose.ui.graphics.painter.b, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(kotlinx.collections.immutable.b bVar, Function1 function1, Function1 function12, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function13;
        Function1 function14;
        androidx.compose.foundation.lazy.grid.A a;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-876815697);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(bVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            function13 = function1;
            i2 |= c0814p2.h(function13) ? 32 : 16;
        } else {
            function13 = function1;
        }
        if ((i & 384) == 0) {
            function14 = function12;
            i2 |= c0814p2.h(function14) ? 256 : 128;
        } else {
            function14 = function12;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.g(z) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            int iD = AbstractC3706q5.d(AbstractC3205m5.g(c0814p2).a);
            androidx.compose.foundation.lazy.grid.A a2 = androidx.compose.foundation.lazy.grid.B.a(0, c0814p2, 3);
            C0426a c0426a = new C0426a(iD);
            androidx.compose.foundation.layout.A0 a0C = AbstractC3706q5.c(z, c0814p2);
            InterfaceC0394k interfaceC0394kE = AbstractC3706q5.e(z);
            InterfaceC0388h interfaceC0388hB = AbstractC3706q5.b(z);
            FillElement fillElement = androidx.compose.foundation.layout.K0.c;
            c0814p2.X(-1670377390);
            boolean zH = ((i2 & 896) == 256) | c0814p2.h(bVar) | c0814p2.f(a2) | ((i2 & 7168) == 2048) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                androidx.navigation.internal.f fVar = new androidx.navigation.internal.f(2, bVar, a2, function14, function13, z);
                a = a2;
                c0814p2.i0(fVar);
                objI = fVar;
            } else {
                a = a2;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3155h0.b(c0426a, fillElement, a, a0C, interfaceC0394kE, interfaceC0388hB, null, false, (Function1) objI, c0814p, 48, 400);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.recyclerview.step.g(bVar, function1, function12, z, i, 6);
        }
    }

    public static final void c(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1965260961);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarU = AbstractC0460p.u(androidx.compose.foundation.layout.K0.c, AbstractC0460p.r(c0814p), false, 14);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.n, c0814p, 54);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.graphics.painter.b bVarA = com.quizlet.themes.e.a(c0814p).d.A(c0814p);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.l();
            AbstractC0460p.c(bVarA, null, androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.k), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 120);
            String strD = AbstractC3106b5.d(c0814p, R.string.library_practice_test_will_appear_here);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).i;
            long jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
            mVar.s();
            androidx.compose.material3.Q4.b(strD, androidx.compose.foundation.layout.K0.o(AbstractC0382e.u(nVar, com.quizlet.ui.resources.designsystem.generated.j.h), com.quizlet.themes.m.x), jE, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65016);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.x(i, 20);
        }
    }

    public static final void d(Function0 function0, Function1 function1, Function1 function12, boolean z, com.quizlet.library.viewmodels.l lVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        com.quizlet.library.viewmodels.l lVar2;
        int i2;
        com.quizlet.library.viewmodels.l lVar3;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1735672781);
        int i3 = i | (c0814p2.h(function0) ? 4 : 2) | (c0814p2.h(function1) ? 32 : 16) | (c0814p2.h(function12) ? 256 : 128) | (c0814p2.g(z) ? 2048 : 1024) | 8192;
        if ((i3 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            lVar3 = lVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                c0814p2.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p2);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p2);
                c0814p2.Y(1729797275);
                c0814p = c0814p2;
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(com.quizlet.library.viewmodels.l.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                lVar2 = (com.quizlet.library.viewmodels.l) w0VarE;
                i2 = i3 & (-57345);
            } else {
                c0814p2.Q();
                i2 = i3 & (-57345);
                lVar2 = lVar;
                c0814p = c0814p2;
            }
            c0814p.q();
            com.quizlet.library.viewmodels.i iVar = (com.quizlet.library.viewmodels.i) AbstractC3409x1.g(lVar2.d, c0814p).getValue();
            if (iVar instanceof com.quizlet.library.viewmodels.f) {
                c0814p.X(-1829077303);
                C0814p c0814p3 = c0814p;
                b(((com.quizlet.library.viewmodels.f) iVar).a, function1, function12, z, c0814p3, i2 & 8176);
                c0814p = c0814p3;
                c0814p.p(false);
            } else if (iVar instanceof com.quizlet.library.viewmodels.g) {
                c0814p.X(-1444466329);
                if (((com.quizlet.library.viewmodels.g) iVar).a) {
                    c0814p.X(-1828764885);
                    C0814p c0814p4 = c0814p;
                    AbstractC3611e6.a(com.quizlet.themes.e.a(c0814p).d.A(c0814p), AbstractC3106b5.d(c0814p, R.string.library_create_practice_test_description), AbstractC3106b5.d(c0814p, R.string.library_create_practice_test_try_now), null, AbstractC3106b5.d(c0814p, R.string.library_create_practice_test_content_description), function0, c0814p4, (i2 << 15) & 458752);
                    c0814p = c0814p4;
                    c0814p.p(false);
                } else {
                    c0814p.X(-1828256609);
                    c(c0814p, 0);
                    c0814p.p(false);
                }
                c0814p.p(false);
            } else {
                if (!Intrinsics.b(iVar, com.quizlet.library.viewmodels.h.a)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-1444477539, c0814p, false);
                }
                c0814p.X(-1444446111);
                C0814p c0814p5 = c0814p;
                AbstractC3249r5.a(null, 0L, c0814p5, 0, 3);
                c0814p = c0814p5;
                c0814p.p(false);
            }
            lVar3 = lVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.b(function0, function1, function12, z, lVar3, i, 12);
        }
    }
}
