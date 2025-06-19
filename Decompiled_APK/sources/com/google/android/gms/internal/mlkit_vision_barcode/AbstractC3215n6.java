package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.res.Configuration;
import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.material3.AbstractC0762y1;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.navigation.compose.C1280m;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3578a5;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.features.achievements.ui.composables.C4218e;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.n6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3215n6 {
    public static final void a(androidx.compose.ui.graphics.painter.b bVar, int i, int i2, String str, Function0 function0, InterfaceC0806l interfaceC0806l, int i3) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1685574791);
        int i4 = i3 | (c0814p.h(bVar) ? 4 : 2) | (c0814p.d(i) ? 32 : 16) | (c0814p.d(i2) ? 256 : 128) | (c0814p.h(function0) ? 16384 : 8192);
        if ((i4 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            c0814p.X(67865212);
            boolean z = (57344 & i4) == 16384;
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new com.quizlet.features.setpage.composable.a(26, function0);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0460p.l(qVarC, false, null, (Function0) objI, 7), str);
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.u();
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.g), androidx.compose.ui.b.k, c0814p, 48);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, g0B, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC2, c0912h4);
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            AbstractC0460p.c(bVar, AbstractC3106b5.d(c0814p, i), androidx.compose.foundation.layout.K0.k(AbstractC0382e.y(nVar, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), 56), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, i4 & 14, 120);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, layoutWeightElement);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            androidx.compose.ui.q qVarC4 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            String strD = AbstractC3106b5.d(c0814p, i);
            androidx.compose.runtime.B b = com.quizlet.themes.w.b;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).g;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(strD, qVarC4, ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 48, 0, 65528);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, i2), androidx.compose.foundation.layout.K0.c(nVar, 1.0f), ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).q, c0814p, 48, 0, 65528);
            c0814p = c0814p;
            c0814p.p(true);
            mVar.q();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, 11);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarO = com.quizlet.ui.resources.icons.d.o(c0814p);
            long jE = ((com.quizlet.themes.b) c0814p.j(b2)).b.e();
            AbstractC0460p.c(bVarO, null, qVarY, null, null, DefinitionKt.NO_Float_VALUE, new C0853m(jE, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(jE, 5) : new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(jE), androidx.compose.ui.graphics.F.E(5))), c0814p, 48, 56);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4218e(bVar, i, i2, str, function0, i3);
        }
    }

    public static final void b(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(43582896);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            C0380d c0380d = AbstractC0398m.a;
            mVar.q();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(f), androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarY);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            int i4 = ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 6;
            g(i4, c0814p, qVarC2, function0);
            d(i4, c0814p, androidx.compose.foundation.layout.K0.c(nVar, 1.0f), function0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.screens.b(i, 7, function0);
        }
    }

    public static final void c(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(336413832);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarP = AbstractC0382e.p(nVar, 1);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarP, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            C0380d c0380d = AbstractC0398m.a;
            mVar.q();
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g(f), androidx.compose.ui.b.j, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarY);
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
            androidx.compose.foundation.layout.I0 i0 = androidx.compose.foundation.layout.I0.a;
            androidx.compose.ui.q qVarA = i0.a(nVar, 1.0f, true);
            FillElement fillElement = androidx.compose.foundation.layout.K0.b;
            androidx.compose.ui.q qVarG = qVarA.g(fillElement);
            int i4 = (i2 << 3) & ContentType.LONG_FORM_ON_DEMAND;
            g(i4, c0814p, qVarG, function0);
            d(i4, c0814p, i0.a(nVar, 1.0f, true).g(fillElement), function0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.screens.b(i, 8, function0);
        }
    }

    public static final void d(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1343276276);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(qVar, null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(990321454, new com.quizlet.quizletandroid.ui.startpage.nav2.composables.d(8, function0), c0814p), c0814p, i2 & 14, 1022);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.U(qVar, function0, i, 13);
        }
    }

    public static final void e(com.quizlet.features.infra.folder.save.screenstates.a aVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.graphics.painter.b bVarD;
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(597310871);
        int i2 = (c0814p.f(aVar) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            int iOrdinal = aVar.ordinal();
            if (iOrdinal == 0) {
                c0814p.X(-1756054829);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                c0814p.X(1278632206);
                bVarD = com.google.android.gms.measurement.internal.Z.d(R.drawable.ic_sys_bookmark_filled, c0814p, 0, false, false);
            } else {
                if (iOrdinal != 1) {
                    throw com.google.android.gms.measurement.internal.Z.j(-1756056964, c0814p, false);
                }
                c0814p.X(-1756052723);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                c0814p.X(-556350770);
                bVarD = com.google.android.gms.measurement.internal.Z.d(R.drawable.ic_sys_bookmark, c0814p, 0, false, false);
            }
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            String str = String.format("SaveMaterialToFolderButtonTestTag-%s", Arrays.copyOf(new Object[]{aVar.name()}, 1));
            Intrinsics.checkNotNullExpressionValue(str, "format(...)");
            function02 = function0;
            AbstractC3578a5.a(bVarD, AbstractC3106b5.d(c0814p, R.string.add_to_folder), androidx.compose.ui.platform.N.G(nVar, str), function02, false, C4076a.e, null, 0L, c0814p, (i2 << 6) & 7168, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_BACKWARD_COMPATIBILITY);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(aVar, function02, i, 17);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0059  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0071  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0093  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00e0  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x014f A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0151  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0196  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0208  */
    /* JADX WARN: Removed duplicated region for block: B:92:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void f(com.quizlet.generated.enums.y1 r18, java.lang.String r19, com.quizlet.features.infra.folder.save.viewmodel.c r20, com.quizlet.features.infra.folder.menu.viewmodel.n r21, androidx.compose.runtime.InterfaceC0806l r22, int r23, int r24) {
        /*
            Method dump skipped, instructions count: 537
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3215n6.f(com.quizlet.generated.enums.y1, java.lang.String, com.quizlet.features.infra.folder.save.viewmodel.c, com.quizlet.features.infra.folder.menu.viewmodel.n, androidx.compose.runtime.l, int, int):void");
    }

    public static final void g(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i2;
        Function0 function02 = function0;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1726312226);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function02) ? 32 : 16;
        }
        int i3 = i2;
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.d();
            androidx.compose.ui.q qVarC = androidx.compose.ui.draw.g.c(qVar, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.g));
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            ((com.quizlet.themes.b) c0814p.j(b)).c.getClass();
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVarC, com.quizlet.ui.resources.designsystem.generated.d.q, androidx.compose.ui.graphics.F.a);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarF);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            C0418x c0418x = C0418x.a;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            AbstractC0460p.c(Z4.a(2131231602, c0814p, 0), null, c0418x.a(nVar, androidx.compose.ui.b.h), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 120);
            androidx.compose.ui.q qVarA = c0418x.a(nVar, androidx.compose.ui.b.i);
            mVar.s();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarA, com.quizlet.ui.resources.designsystem.generated.j.h);
            mVar.j();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(qVarU, com.quizlet.ui.resources.designsystem.generated.h.i), "scanAssetNavigationButton");
            long jG = ((com.quizlet.themes.b) c0814p.j(b)).G();
            androidx.compose.foundation.shape.d dVar = androidx.compose.foundation.shape.e.a;
            androidx.compose.runtime.internal.d dVar2 = com.quizlet.upgrade.confirmation.composables.b.a;
            function02 = function0;
            AbstractC0762y1.a(function02, qVarG, dVar, jG, 0L, null, c0814p, ((i3 >> 3) & 14) | 12582912);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.U(qVar, function02, i, 12);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00b3  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0177  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0187  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x01a2  */
    /* JADX WARN: Removed duplicated region for block: B:56:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void h(int r34, int r35, int r36, androidx.compose.runtime.InterfaceC0806l r37, androidx.compose.ui.q r38, kotlin.jvm.functions.Function0 r39) {
        /*
            Method dump skipped, instructions count: 428
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3215n6.h(int, int, int, androidx.compose.runtime.l, androidx.compose.ui.q, kotlin.jvm.functions.Function0):void");
    }

    public static androidx.core.os.f i(Configuration configuration) {
        return new androidx.core.os.f(new androidx.core.os.g(configuration.getLocales()));
    }
}
