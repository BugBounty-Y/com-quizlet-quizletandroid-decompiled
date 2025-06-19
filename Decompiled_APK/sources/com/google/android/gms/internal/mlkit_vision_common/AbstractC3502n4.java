package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3642i5;
import com.quizlet.assembly.compose.buttons.C4095u;
import com.quizlet.features.achievements.ui.composables.C4215b;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.n4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3502n4 {
    public static final void a(androidx.camera.core.impl.utils.e eVar, int i, Function0 function0, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        int i4;
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1335699980);
        if ((i2 & 6) == 0) {
            i3 = ((i2 & 8) == 0 ? c0814p.f(eVar) : c0814p.h(eVar) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 = i;
            i3 |= c0814p.d(i4) ? 32 : 16;
        } else {
            i4 = i;
        }
        if ((i2 & 384) == 0) {
            function02 = function0;
            i3 |= c0814p.h(function02) ? 256 : 128;
        } else {
            function02 = function0;
        }
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i5 = c0814p.P;
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
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            com.quizlet.themes.m.g.t();
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.k, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g, androidx.compose.ui.b.k, c0814p, 54);
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarC2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.nav2_models_list_title_achievements), null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).f, c0814p, 0, 0, 65534);
            AbstractC3586b5.a(AbstractC3106b5.d(c0814p, R.string.view_all), null, function02, false, null, C4095u.a, null, null, null, c0814p, i3 & 896, 986);
            c0814p.p(true);
            com.facebook.appevents.m.a(eVar, function0, androidx.compose.ui.platform.N.G(nVar, "achievementsCard"), i4, c0814p, (i3 & 14) | 384 | ((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i3 << 6) & 7168));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.n(eVar, i, function0, i2, 3);
        }
    }

    public static final void b(com.quizlet.features.userprofile.data.a aVar, boolean z, androidx.camera.core.impl.utils.e eVar, int i, Function0 function0, Function0 function02, Function0 function03, Function0 function04, androidx.compose.ui.q qVar, Integer num, InterfaceC0806l interfaceC0806l, int i2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(964693768);
        int i3 = i2 | (c0814p.f(aVar) ? 4 : 2) | (c0814p.g(z) ? 32 : 16) | (c0814p.f(eVar) ? 256 : 128) | (c0814p.d(i) ? 2048 : 1024) | (c0814p.h(function0) ? 16384 : 8192) | (c0814p.h(function02) ? 131072 : 65536) | (c0814p.h(function03) ? 1048576 : 524288) | (c0814p.h(function04) ? 8388608 : 4194304) | (c0814p.f(qVar) ? 67108864 : 33554432) | (c0814p.f(num) ? 536870912 : 268435456);
        if ((306783379 & i3) == 306783378 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(AbstractC0460p.u(qVar, AbstractC0460p.r(c0814p), false, 14), 1.0f), "userProfileContentColumn");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p, 48);
            int i4 = c0814p.P;
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
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, com.quizlet.ui.resources.designsystem.generated.j.i));
            int i5 = i3 >> 6;
            f(aVar.a, aVar.b, function0, c0814p, i5 & 896);
            mVar.p();
            c(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), z, num, function02, function04, c0814p, (i3 & ContentType.LONG_FORM_ON_DEMAND) | ((i3 >> 21) & 896) | (i5 & 7168) | ((i3 >> 9) & 57344));
            c0814p.X(1724490734);
            if (eVar != null) {
                a(eVar, i, function03, c0814p, (i5 & 126) | ((i3 >> 12) & 896));
            }
            c0814p.p(false);
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, ((androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f)).O(C0380d.e(c0814p).e.e().d) + f));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.k(aVar, z, eVar, i, function0, function02, function03, function04, qVar, num, i2);
        }
    }

    public static final void c(androidx.compose.ui.q qVar, boolean z, Integer num, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(783235932);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(num) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function0) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function02) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar, "userProfileContentProfileButtonsColumn");
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.s();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h), androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            AbstractC3496m4.a(com.quizlet.features.userprofile.ui.a.c, androidx.compose.ui.platform.N.G(nVar, "yourSettings"), null, function0, c0814p, (i2 & 7168) | 54, 4);
            c0814p.X(-1503640439);
            if (z) {
                AbstractC3496m4.a(com.quizlet.features.userprofile.ui.a.d, androidx.compose.ui.platform.N.G(nVar, "activity"), androidx.compose.runtime.internal.e.e(-333130537, new com.quizlet.assembly.compose.cards.c(num, 24), c0814p), function02, c0814p, ((i2 >> 3) & 7168) | 438, 0);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.addtofolder.composables.q(qVar, z, num, function0, function02, i);
        }
    }

    public static final void d(final com.quizlet.features.userprofile.data.a aVar, final androidx.camera.core.impl.utils.e eVar, final int i, final androidx.compose.ui.q qVar, final boolean z, final Integer num, final Function0 function0, final Function0 function02, final Function0 function03, final Function0 function04, final Function0 function05, final Function0 function06, InterfaceC0806l interfaceC0806l, final int i2) {
        int i3;
        int i4;
        Integer num2;
        Function0 function07;
        androidx.compose.ui.graphics.painter.b bVarM;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1036918887);
        if ((i2 & 6) == 0) {
            i3 = (c0814p2.f(aVar) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= (i2 & 64) == 0 ? c0814p2.f(eVar) : c0814p2.h(eVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i4 = i;
            i3 |= c0814p2.d(i4) ? 256 : 128;
        } else {
            i4 = i;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p2.f(qVar) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i3 |= c0814p2.g(z) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            num2 = num;
            i3 |= c0814p2.f(num2) ? 131072 : 65536;
        } else {
            num2 = num;
        }
        if ((1572864 & i2) == 0) {
            function07 = function0;
            i3 |= c0814p2.h(function07) ? 1048576 : 524288;
        } else {
            function07 = function0;
        }
        if ((12582912 & i2) == 0) {
            i3 |= c0814p2.h(function02) ? 8388608 : 4194304;
        }
        if ((100663296 & i2) == 0) {
            i3 |= c0814p2.h(function03) ? 67108864 : 33554432;
        }
        if ((i2 & 805306368) == 0) {
            i3 |= c0814p2.h(function04) ? 536870912 : 268435456;
        }
        int i5 = i3;
        int i6 = (c0814p2.h(function05) ? (char) 4 : (char) 2) | (c0814p2.h(function06) ? ' ' : (char) 16);
        if ((i5 & 306783379) == 306783378 && (i6 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.X(1937124513);
            if (z) {
                com.quizlet.themes.e.a(c0814p2).a.getClass();
                bVarM = com.quizlet.ui.resources.icons.d.m(c0814p2);
            } else {
                bVarM = null;
            }
            androidx.compose.ui.graphics.painter.b bVar = bVarM;
            c0814p2.p(false);
            c0814p2.X(1937128058);
            String strD = z ? AbstractC3106b5.d(c0814p2, R.string.profile) : "";
            c0814p2.p(false);
            long jG = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g();
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(qVar, androidx.compose.runtime.internal.e.e(922472995, new androidx.navigation.compose.p(strD, bVar, function06, aVar, function07, 6), c0814p2), null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(-253844680, new com.quizlet.features.userprofile.ui.f(aVar, z, eVar, i4, function02, function03, function04, function05, num2), c0814p2), c0814p, ((i5 >> 9) & 14) | 805306416, 188);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.userprofile.ui.e
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i2 | 1);
                    Function0 function08 = function05;
                    Function0 function09 = function06;
                    AbstractC3502n4.d(aVar, eVar, i, qVar, z, num, function0, function02, function03, function04, function08, function09, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void e(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0, boolean z) {
        androidx.compose.ui.q qVar2;
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1167793163);
        int i2 = (c0814p.g(z) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
            function02 = function0;
        } else {
            qVar2 = qVar;
            function02 = function0;
            AbstractC3642i5.b(((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i2 << 3) & 896), 0, c0814p, qVar2, AbstractC3106b5.d(c0814p, z ? R.string.free_trial : R.string.upgrade), function02);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4215b(z, function02, qVar2, i, 1);
        }
    }

    public static final void f(String str, String str2, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2022320267);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(str) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(str2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, gVar, c0814p, 48);
            int i3 = c0814p.P;
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
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_sys_image_gray400, c0814p, 0);
            androidx.compose.ui.graphics.painter.b bVarA2 = Z4.a(R.drawable.ic_sys_image_gray400, c0814p, 0);
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.draw.g.c(nVar, androidx.compose.foundation.shape.e.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            com.google.android.gms.internal.mlkit_vision_camera.r3.b(str, str2, androidx.compose.ui.platform.N.G(AbstractC0460p.l(androidx.compose.foundation.layout.K0.k(qVarC2, com.quizlet.themes.m.y), false, null, function0, 7), "profileImage"), bVarA, bVarA2, c0814p, i2 & 126, 32736);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).f;
            long jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
            mVar.s();
            androidx.compose.material3.Q4.b(str2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, (i2 >> 3) & 14, 0, 65528);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 13, str, str2, function0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:119:0x03fc  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0419  */
    /* JADX WARN: Removed duplicated region for block: B:125:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0081  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x009b  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00a7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void g(int r27, com.quizlet.features.userprofile.navigation.b r28, androidx.compose.ui.q r29, com.quizlet.features.userprofile.data.x r30, boolean r31, kotlin.jvm.functions.Function0 r32, androidx.compose.runtime.InterfaceC0806l r33, int r34, int r35) {
        /*
            Method dump skipped, instructions count: 1057
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4.g(int, com.quizlet.features.userprofile.navigation.b, androidx.compose.ui.q, com.quizlet.features.userprofile.data.x, boolean, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    public static void h(Object obj, Object obj2) {
        if (obj == null) {
            throw new NullPointerException(androidx.compose.ui.node.B.e(obj2, "null key in entry: null="));
        }
        if (obj2 != null) {
            return;
        }
        throw new NullPointerException("null value in entry: " + obj + "=null");
    }

    public static void i(int i, String str) {
        if (i >= 0) {
            return;
        }
        throw new IllegalArgumentException(str + " cannot be negative but was: " + i);
    }
}
