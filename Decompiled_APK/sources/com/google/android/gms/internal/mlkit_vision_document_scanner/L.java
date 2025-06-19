package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.AbstractC0809m0;
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
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.quizlet.assembly.compose.buttons.C4079d;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class L {
    public static final void a(Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, Function0 function06, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-536293248);
        int i2 = i | (c0814p.h(function0) ? 4 : 2) | (c0814p.h(function02) ? 32 : 16) | (c0814p.h(function03) ? 256 : 128) | (c0814p.h(function04) ? 2048 : 1024) | (c0814p.h(function05) ? 16384 : 8192) | (c0814p.h(function06) ? 131072 : 65536) | (c0814p.f(qVar) ? 1048576 : 524288);
        if ((599187 & i2) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            C0386g c0386g = AbstractC0398m.e;
            androidx.compose.ui.q qVarU = AbstractC0460p.u(qVar.g(androidx.compose.foundation.layout.K0.c), AbstractC0460p.r(c0814p), false, 14);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarU, DefinitionKt.NO_Float_VALUE, f, 1);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0386g, gVar, c0814p, 54);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarW);
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
            d(null, c0814p, 0);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            mVar.q();
            h(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, 0);
            mVar.q();
            F.a((i2 >> 6) & 126, c0814p, AbstractC0382e.w(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), com.quizlet.themes.m.w0, DefinitionKt.NO_Float_VALUE, 2), function03, function04);
            mVar.q();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            float f2 = f;
            mVar.q();
            androidx.compose.ui.q qVarW2 = AbstractC0382e.w(qVarY, f2, DefinitionKt.NO_Float_VALUE, 2);
            float f3 = com.quizlet.themes.m.t0;
            AbstractC3626g5.b((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND, c0814p, androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.K0.q(qVarW2, DefinitionKt.NO_Float_VALUE, f3, 1), 1.0f), function0);
            mVar.s();
            androidx.compose.ui.q qVarY2 = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            mVar.q();
            b((i2 >> 3) & 14, c0814p, androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.K0.q(AbstractC0382e.w(qVarY2, f2, DefinitionKt.NO_Float_VALUE, 2), DefinitionKt.NO_Float_VALUE, f3, 1), 1.0f), function02);
            if (Float.compare(androidx.compose.ui.unit.g.b(AbstractC3205m5.d((Context) c0814p.j(AndroidCompositionLocals_androidKt.b))), 400) <= 0) {
                mVar.q();
            } else {
                mVar.p();
                f2 = com.quizlet.ui.resources.designsystem.generated.j.j;
            }
            f((i2 >> 9) & ContentType.LONG_FORM_ON_DEMAND, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function05);
            c(function06, c0814p, (i2 >> 15) & 14);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4079d(function0, function02, function03, function04, function05, function06, qVar, i, 4);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1439217364);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            String strD = AbstractC3106b5.d(c0814p2, R.string.sign_up_with_email);
            C4097w c4097w = C4097w.a;
            com.quizlet.themes.e.a(c0814p2).a.getClass();
            c0814p2.X(531300590);
            androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_sys_mail, c0814p2, 0);
            c0814p2.p(false);
            c0814p = c0814p2;
            Y4.a(strD, qVar, function0, false, false, null, null, 0L, 0L, c4097w, bVarA, null, false, c0814p, (i2 & ContentType.LONG_FORM_ON_DEMAND) | ((i2 << 6) & 896), 0, 6648);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.U(function0, qVar, i, 5);
        }
    }

    public static final void c(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1720878550);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.screens.b(i, 5, function0);
        }
    }

    public static final void d(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1860366907);
        if (((i | 6) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            qVar = androidx.compose.ui.n.b;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.b, false);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            AbstractC0460p.c(com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(2131231760, c0814p, 0), null, androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(qVar, com.quizlet.themes.m.v0), "imageLogo"), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 120);
            AbstractC0460p.c(com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(2131231591, c0814p, 0), null, AbstractC0382e.y(qVar, com.quizlet.themes.m.u0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 120);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 17, qVar);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:116:0x02c9  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x02f6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void e(kotlin.jvm.functions.Function1 r32, kotlin.jvm.functions.Function0 r33, kotlin.jvm.functions.Function0 r34, kotlin.jvm.functions.Function0 r35, kotlin.jvm.functions.Function0 r36, kotlin.jvm.functions.Function1 r37, kotlin.jvm.functions.Function2 r38, kotlin.jvm.functions.Function0 r39, kotlin.jvm.functions.Function0 r40, com.quizlet.login.intro.viewmodel.a r41, com.quizlet.features.infra.google.e r42, androidx.compose.runtime.InterfaceC0806l r43, int r44) {
        /*
            Method dump skipped, instructions count: 845
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.L.e(kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, com.quizlet.login.intro.viewmodel.a, com.quizlet.features.infra.google.e, androidx.compose.runtime.l, int):void");
    }

    public static final void f(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-924395177);
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
            String strD = AbstractC3106b5.d(c0814p, R.string.login_have_an_account_text);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.login_login_highlighted);
            c0814p.X(-374016308);
            C0984d c0984d = new C0984d();
            AbstractC0809m0 abstractC0809m0 = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(abstractC0809m0)).o;
            AbstractC0809m0 abstractC0809m02 = com.quizlet.themes.g.a;
            int i3 = c0984d.i(androidx.compose.ui.text.L.b(l, ((com.quizlet.themes.b) c0814p.j(abstractC0809m02)).b.e(), 0L, null, null, 0L, 0, 0L, null, 16777214).a);
            try {
                c0984d.f(strD);
                Unit unit = Unit.a;
                c0984d.h(i3);
                int iM = StringsKt.M(strD, strD2, 0, true, 2);
                int length = strD2.length() + iM;
                c0814p.X(-374003108);
                if (iM >= 0 && length > 0) {
                    c0984d.c(androidx.compose.ui.text.L.b(((com.quizlet.themes.f) c0814p.j(abstractC0809m0)).j, ((com.quizlet.themes.b) c0814p.j(abstractC0809m02)).e, 0L, null, null, 0L, 0, 0L, null, 16777214).a, StringsKt.M(strD, strD2, 0, false, 6), strD2.length() + StringsKt.M(strD, strD2, 0, false, 6));
                    c0984d.b("login", StringsKt.M(strD, strD2, 0, false, 6), "login", strD2.length() + StringsKt.M(strD, strD2, 0, false, 6));
                }
                c0814p.p(false);
                C0995g c0995gJ = c0984d.j();
                c0814p.p(false);
                androidx.compose.ui.text.L lB = androidx.compose.ui.text.L.b(androidx.compose.ui.text.L.d, 0L, 0L, null, null, 0L, 3, 0L, null, 16744447);
                c0814p.X(-373979324);
                boolean zF = c0814p.f(c0995gJ) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
                Object objI = c0814p.I();
                if (zF || objI == C0804k.a) {
                    objI = new com.quizlet.explanations.solution.solutionwall.limitedcontent.a(c0995gJ, function0, 1);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                AbstractC0484d0.c(c0995gJ, qVar, lB, false, 0, 0, null, (Function1) objI, c0814p, (i2 << 3) & ContentType.LONG_FORM_ON_DEMAND);
            } catch (Throwable th) {
                c0984d.h(i3);
                throw th;
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.U(qVar, function0, i, 4);
        }
    }

    public static final void g(com.quizlet.login.intro.data.u uVar, androidx.compose.ui.q qVar, Function1 function1, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z;
        com.quizlet.login.intro.data.u uVar2;
        C0814p c0814p;
        androidx.compose.ui.q qVar2;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1954519409);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(uVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i & 384) == 0) {
            i3 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p2.h(function0) ? 2048 : 1024;
        }
        int i4 = i3;
        if ((i4 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            qVar2 = qVar;
            c0814p = c0814p2;
            uVar2 = uVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            com.quizlet.assembly.compose.toasts.g gVarD = AbstractC3667l6.d(c0814p2);
            c0814p2.X(-1186239416);
            c0814p2.X(-551691343);
            Object objI = c0814p2.I();
            if (objI == v) {
                objI = new com.quizlet.assembly.compose.toasts.g(Long.MAX_VALUE);
                c0814p2.i0(objI);
            }
            com.quizlet.assembly.compose.toasts.g gVar = (com.quizlet.assembly.compose.toasts.g) objI;
            c0814p2.p(false);
            c0814p2.p(false);
            c0814p2.X(-116188277);
            boolean zH = ((i4 & 14) == 4) | c0814p2.h(gVarD) | c0814p2.h(gVar);
            Object objI2 = c0814p2.I();
            if (zH || objI2 == v) {
                objI2 = new com.quizlet.login.intro.ui.j(uVar, gVarD, gVar, null);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            C0776c.f(c0814p2, uVar, (Function2) objI2);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "introScreen");
            long jG = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g();
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            AbstractC0725t3.a(qVarG, null, null, androidx.compose.runtime.internal.e.e(-1740637973, new com.quizlet.assembly.compose.buttons.A(uVar, function1, gVarD, gVar, 17), c0814p2), null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(-771200382, new com.quizlet.features.questiontypes.mcq.ui.c(8, function1, function0), c0814p2), c0814p2, 805309440, 182);
            com.quizlet.features.infra.compatibility.a aVar = uVar.c;
            c0814p2.X(-116122355);
            if (aVar != null) {
                com.google.android.gms.internal.mlkit_vision_barcode.C5.a(aVar, null, c0814p2, 0);
                Unit unit = Unit.a;
            }
            c0814p2.p(false);
            c0814p2.X(-116117938);
            com.quizlet.login.authentication.k kVar = uVar.d;
            if (kVar == null) {
                uVar2 = uVar;
                c0814p = c0814p2;
                z = false;
            } else {
                c0814p2.X(499717555);
                int i5 = i4 & 896;
                boolean z2 = i5 == 256;
                Object objI3 = c0814p2.I();
                if (z2 || objI3 == v) {
                    objI3 = new com.quizlet.features.practicetest.detail.m(24, function1);
                    c0814p2.i0(objI3);
                }
                Function0 function02 = (Function0) objI3;
                c0814p2.p(false);
                c0814p2.X(499715379);
                boolean z3 = i5 == 256;
                Object objI4 = c0814p2.I();
                if (z3 || objI4 == v) {
                    objI4 = new com.quizlet.features.practicetest.detail.m(25, function1);
                    c0814p2.i0(objI4);
                }
                c0814p2.p(false);
                z = false;
                uVar2 = uVar;
                G.b(kVar, function02, (Function0) objI4, null, c0814p2, 0);
                c0814p = c0814p2;
                Unit unit2 = Unit.a;
            }
            c0814p.p(z);
            if (uVar2.e) {
                AbstractC3249r5.a(null, 0L, c0814p, 0, 3);
            }
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i((Object) uVar2, (Object) qVar2, function1, (Object) function0, i, 27);
        }
    }

    public static final void h(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1443137508);
        int i2 = i | (c0814p2.f(qVar) ? 4 : 2);
        if ((i2 & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.login_title), qVar, 0L, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).c(), c0814p, (i2 << 3) & ContentType.LONG_FORM_ON_DEMAND, 0, 65020);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 18, qVar);
        }
    }

    public static void i(JSONObject jSONObject, SharedPreferences.Editor editor, String str) {
        editor.putString(str, jSONObject.toString()).apply();
    }
}
