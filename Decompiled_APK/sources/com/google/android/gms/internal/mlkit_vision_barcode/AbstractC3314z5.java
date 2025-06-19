package com.google.android.gms.internal.mlkit_vision_barcode;

import android.graphics.ColorFilter;
import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.foundation.layout.FillElement;
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
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.C1011l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3314z5;
import com.quizlet.assembly.compose.buttons.C4093s;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.assembly.compose.buttons.InterfaceC4099y;
import com.quizlet.features.achievements.ui.composables.C4218e;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.z5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3314z5 {
    public static final void a(com.quizlet.features.infra.basestudy.ui.models.a data, androidx.compose.ui.q qVar, Function1 function1, int i, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        androidx.compose.ui.q qVar2;
        int i4;
        Function1 function12;
        int i5;
        Function1 function13;
        int i6;
        int i7;
        Function1 function14;
        androidx.compose.ui.n nVar;
        androidx.compose.ui.q qVar3;
        Intrinsics.checkNotNullParameter(data, "data");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(58167837);
        int i8 = i2 | (c0814p.h(data) ? 4 : 2);
        int i9 = i3 & 2;
        if (i9 != 0) {
            i4 = i8 | 48;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i4 = i8 | (c0814p.f(qVar2) ? 32 : 16);
        }
        int i10 = i3 & 4;
        if (i10 != 0) {
            i5 = i4 | 384;
            function12 = function1;
        } else {
            function12 = function1;
            i5 = i4 | (c0814p.h(function12) ? 256 : 128);
        }
        int i11 = i5 | 1024;
        if ((i11 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar2;
            function14 = function12;
        } else {
            c0814p.S();
            int i12 = i2 & 1;
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            if (i12 == 0 || c0814p.w()) {
                if (i9 != 0) {
                    qVar2 = nVar2;
                }
                if (i10 != 0) {
                    c0814p.X(-1472175811);
                    Object objI = c0814p.I();
                    if (objI == C0804k.a) {
                        objI = new C4237k(13);
                        c0814p.i0(objI);
                    }
                    function13 = (Function1) objI;
                    c0814p.p(false);
                } else {
                    function13 = function12;
                }
                i6 = i11 & (-7169);
                i7 = AbstractC3205m5.g(c0814p).a;
                function14 = function13;
            } else {
                c0814p.Q();
                int i13 = i11 & (-7169);
                i7 = i;
                i6 = i13;
                function14 = function12;
            }
            androidx.compose.ui.q qVar4 = qVar2;
            c0814p.q();
            FillElement fillElement = androidx.compose.foundation.layout.K0.c;
            androidx.compose.ui.q qVarG = qVar4.g(fillElement);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i14 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, kE, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i14))) {
                android.support.v4.media.session.a.z(i14, c0814p, i14, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            C0418x c0418x = C0418x.a;
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            C0386g c0386g = AbstractC0398m.e;
            androidx.compose.ui.q qVarG2 = androidx.compose.ui.platform.N.G(nVar2, "error_content_test_tag").g(fillElement);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0386g, gVar, c0814p, 54);
            int i15 = c0814p.P;
            i = i7;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarG2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i15))) {
                android.support.v4.media.session.a.z(i15, c0814p, i15, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            float f = com.quizlet.themes.m.Y0;
            androidx.compose.ui.q qVarQ = androidx.compose.foundation.layout.K0.q(nVar2, DefinitionKt.NO_Float_VALUE, f, 1);
            mVar.q();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarQ, f2);
            androidx.compose.foundation.layout.B bA2 = androidx.compose.foundation.layout.A.a(c0386g, gVar, c0814p, 54);
            int i16 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarU);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i16))) {
                android.support.v4.media.session.a.z(i16, c0814p, i16, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            mVar.l();
            AbstractC0460p.c(data.c, data.d, androidx.compose.foundation.layout.K0.k(nVar2, com.quizlet.ui.resources.designsystem.generated.h.k), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 0, 120);
            androidx.compose.ui.text.L lB = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).b();
            long jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
            androidx.compose.runtime.B b = com.quizlet.themes.l.a;
            androidx.compose.material3.Q4.b(data.a, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, ((com.quizlet.themes.j) c0814p.j(b)).d(), DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jE, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, lB, c0814p, 0, 0, 65016);
            c0814p = c0814p;
            c0814p.X(-891699192);
            String str = data.b;
            if (str == null) {
                nVar = nVar2;
            } else {
                nVar = nVar2;
                b((i6 >> 3) & ContentType.LONG_FORM_ON_DEMAND, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, ((com.quizlet.themes.j) c0814p.j(b)).d(), DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), str, function14);
                Unit unit = Unit.a;
            }
            androidx.compose.ui.node.B.s(c0814p, false, true, true);
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            androidx.compose.ui.q qVarC4 = i == 0 ? androidx.compose.foundation.layout.K0.c(nVar, 1.0f) : nVar;
            InterfaceC4099y interfaceC4099y = i == 0 ? C4093s.a : C4097w.a;
            c0814p.X(1975232415);
            String str2 = data.e;
            if (str2 != null) {
                androidx.compose.ui.q qVarQ2 = androidx.compose.foundation.layout.K0.q(c0418x.a(qVarC4, androidx.compose.ui.b.h), DefinitionKt.NO_Float_VALUE, f, 1);
                mVar.q();
                mVar.v();
                com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(str2, AbstractC0382e.v(qVarQ2, f2, com.quizlet.ui.resources.designsystem.generated.j.l), data.f, false, null, interfaceC4099y, null, null, null, false, c0814p, 0, 984);
                c0814p = c0814p;
                Unit unit2 = Unit.a;
            }
            c0814p.p(false);
            c0814p.p(true);
            qVar3 = qVar4;
        }
        int i17 = i;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4218e(data, qVar3, function14, i17, i2, i3);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str, Function1 function1) {
        int i2;
        androidx.compose.ui.q qVar2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1295362795);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(str) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(function1) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            qVar2 = qVar;
            i2 |= c0814p2.f(qVar2) ? 256 : 128;
        } else {
            qVar2 = qVar;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            String strD = AbstractC3106b5.d(c0814p2, R.string.help_center_highlighted);
            c0814p2.X(1076054695);
            C0984d c0984d = new C0984d();
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            int i3 = c0984d.i(new androidx.compose.ui.text.D(((com.quizlet.themes.b) c0814p2.j(b)).b.e(), 0L, (androidx.compose.ui.text.font.u) null, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, (androidx.compose.ui.text.font.j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65534));
            try {
                c0984d.f(str);
                Unit unit = Unit.a;
                c0984d.h(i3);
                int iM = StringsKt.M(str, strD, 0, true, 2);
                int length = strD.length() + iM;
                c0814p2.X(1076066314);
                if (iM >= 0 && length > 0) {
                    c0984d.c(new androidx.compose.ui.text.D(((com.quizlet.themes.b) c0814p2.j(b)).e, 0L, (androidx.compose.ui.text.font.u) null, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, com.quizlet.ui.resources.designsystem.generated.a.e, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65502), iM, length);
                    c0984d.b("help_center_tag", iM, "help_center_tag", length);
                    c0814p2.X(-1516500602);
                    boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
                    Object objI = c0814p2.I();
                    if (z || objI == C0804k.a) {
                        objI = new com.quizlet.features.infra.basestudy.ui.c(0, function1);
                        c0814p2.i0(objI);
                    }
                    c0814p2.p(false);
                    c0984d.a(new C1011l("help_center_tag", null, (com.quizlet.features.infra.basestudy.ui.c) objI), iM, length);
                }
                c0814p2.p(false);
                C0995g c0995gJ = c0984d.j();
                c0814p2.p(false);
                c0814p = c0814p2;
                androidx.compose.material3.Q4.c(c0995gJ, qVar2, ((com.quizlet.themes.b) c0814p2.j(b)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, null, androidx.compose.ui.text.L.b(((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).a(), 0L, 0L, null, null, 0L, 3, 0L, null, 16744447), c0814p, (i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND, 0, 131064);
            } catch (Throwable th) {
                c0984d.h(i3);
                throw th;
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.basestudy.ui.d(i, 0, qVar, str, function1);
        }
    }

    public static final void c(final String searchHint, final androidx.compose.ui.q qVar, final Function0 function0, final long j, final long j2, final float f, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        ColorFilter porterDuffColorFilter;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(searchHint, "searchHint");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(491653425);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(searchHint) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function0) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.e(j) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.e(j2) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.c(f) ? 131072 : 65536;
        }
        if ((74899 & i2) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            int i3 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i3 != 0 && !c0814p2.w()) {
                c0814p2.Q();
            }
            c0814p2.q();
            androidx.compose.ui.q qVarD = androidx.compose.foundation.layout.K0.d(androidx.compose.foundation.layout.K0.c(qVar, 1.0f), f);
            androidx.compose.foundation.shape.d dVar = androidx.compose.foundation.shape.e.a;
            androidx.compose.ui.q qVarC = androidx.compose.ui.draw.g.c(AbstractC0460p.f(qVarD, j, dVar), dVar);
            c0814p2.X(799220649);
            boolean z = (i2 & 896) == 256;
            Object objI = c0814p2.I();
            if (z || objI == v) {
                objI = new com.quizlet.features.setpage.composable.a(24, function0);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            androidx.compose.ui.q qVarL = AbstractC0460p.l(qVarC, false, null, (Function0) objI, 7);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p2, 48);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarL);
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
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC2, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14);
            com.quizlet.themes.e.a(c0814p2).a.getClass();
            int i5 = i2;
            androidx.compose.ui.graphics.painter.b bVarH = com.quizlet.ui.resources.icons.d.H(c0814p2);
            String strD = AbstractC3106b5.d(c0814p2, R.string.search);
            int i6 = 5;
            if (Build.VERSION.SDK_INT >= 29) {
                porterDuffColorFilter = C0854n.a.a(j2, 5);
            } else {
                porterDuffColorFilter = new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(j2), androidx.compose.ui.graphics.F.E(5));
                i6 = 5;
            }
            AbstractC0460p.c(bVarH, strD, qVarY, null, null, DefinitionKt.NO_Float_VALUE, new C0853m(j2, i6, porterDuffColorFilter), c0814p2, 0, 56);
            mVar.u();
            float f3 = com.quizlet.ui.resources.designsystem.generated.j.g;
            mVar.s();
            androidx.compose.material3.Q4.b(searchHint, AbstractC0382e.y(nVar, f3, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, 10), j2, 0L, null, 0L, null, 0L, 2, false, 1, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).j, c0814p2, (i5 & 14) | ((i5 >> 6) & 896), 3120, 55288);
            c0814p = c0814p2;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.ui.compose.y
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    long j3 = j2;
                    float f4 = f;
                    AbstractC3314z5.c(searchHint, qVar, function0, j, j3, f4, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }
}
