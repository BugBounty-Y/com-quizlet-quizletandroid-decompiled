package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
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
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4716l;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Y5 {
    public static final void a(androidx.compose.ui.q qVar, float f, Function2 function2, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-849064490);
        int i4 = i2 & 1;
        if (i4 != 0) {
            i3 = i | 6;
        } else {
            i3 = (c0814p.f(qVar) ? 4 : 2) | i;
        }
        if (((i3 | (((i2 & 2) == 0 && c0814p.c(f)) ? 32 : 16)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                if (i4 != 0) {
                    qVar = androidx.compose.ui.n.b;
                }
                if ((i2 & 2) != 0) {
                    com.quizlet.themes.m.g.d();
                    f = com.quizlet.ui.resources.designsystem.generated.f.g;
                }
            } else {
                c0814p.Q();
            }
            c0814p.q();
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.ui.draw.g.c(qVar, androidx.compose.foundation.shape.e.a(f)), 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            function2.invoke(c0814p, 6);
            c0814p.p(true);
        }
        androidx.compose.ui.q qVar2 = qVar;
        float f2 = f;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.a(qVar2, f2, function2, i, i2);
        }
    }

    public static final void b(C4716l c4716l, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, InterfaceC0806l interfaceC0806l, int i, int i2) {
        Function0 function06;
        int i3;
        Function0 function07;
        int i4;
        Function0 function08;
        int i5;
        Function0 function09;
        int i6;
        Function0 function010;
        int i7;
        Function0 function011;
        Function0 function012;
        Function0 function013;
        Function0 function014;
        Function0 function015;
        Function0 function016;
        Function0 function017;
        C0814p c0814p;
        Function0 function018;
        Function0 function019;
        Function0 function020;
        Function0 function021;
        Function0 function022;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1152454803);
        int i8 = i | (c0814p2.f(c4716l) ? 4 : 2);
        int i9 = i2 & 2;
        if (i9 != 0) {
            i3 = i8 | 48;
            function06 = function0;
        } else {
            function06 = function0;
            i3 = i8 | (c0814p2.h(function06) ? 32 : 16);
        }
        int i10 = i2 & 4;
        if (i10 != 0) {
            i4 = i3 | 384;
            function07 = function02;
        } else {
            function07 = function02;
            i4 = i3 | (c0814p2.h(function07) ? 256 : 128);
        }
        int i11 = i2 & 8;
        if (i11 != 0) {
            i5 = i4 | 3072;
            function08 = function03;
        } else {
            function08 = function03;
            i5 = i4 | (c0814p2.h(function08) ? 2048 : 1024);
        }
        int i12 = i2 & 16;
        if (i12 != 0) {
            i6 = i5 | 24576;
            function09 = function04;
        } else {
            function09 = function04;
            i6 = i5 | (c0814p2.h(function09) ? 16384 : 8192);
        }
        int i13 = i2 & 32;
        if (i13 != 0) {
            i7 = i6 | 196608;
            function010 = function05;
        } else {
            function010 = function05;
            i7 = i6 | (c0814p2.h(function010) ? 131072 : 65536);
        }
        if ((74899 & i7) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            function022 = function06;
            function021 = function07;
            c0814p = c0814p2;
            function020 = function08;
            function019 = function09;
            function018 = function010;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            if (i9 != 0) {
                c0814p2.X(-1181774693);
                Object objI = c0814p2.I();
                if (objI == v) {
                    objI = new com.quizlet.login.resetpassword.ui.a(26);
                    c0814p2.i0(objI);
                }
                function011 = (Function0) objI;
                c0814p2.p(false);
            } else {
                function011 = function06;
            }
            if (i10 != 0) {
                c0814p2.X(-1181773381);
                Object objI2 = c0814p2.I();
                if (objI2 == v) {
                    objI2 = new com.quizlet.login.resetpassword.ui.a(27);
                    c0814p2.i0(objI2);
                }
                function012 = (Function0) objI2;
                c0814p2.p(false);
            } else {
                function012 = function07;
            }
            if (i11 != 0) {
                c0814p2.X(-1181772069);
                Object objI3 = c0814p2.I();
                if (objI3 == v) {
                    objI3 = new com.quizlet.login.resetpassword.ui.a(28);
                    c0814p2.i0(objI3);
                }
                c0814p2.p(false);
                function08 = (Function0) objI3;
            }
            if (i12 != 0) {
                c0814p2.X(-1181770885);
                Object objI4 = c0814p2.I();
                if (objI4 == v) {
                    objI4 = new com.quizlet.login.resetpassword.ui.a(29);
                    c0814p2.i0(objI4);
                }
                function013 = (Function0) objI4;
                c0814p2.p(false);
            } else {
                function013 = function09;
            }
            if (i13 != 0) {
                c0814p2.X(-1181769733);
                Object objI5 = c0814p2.I();
                if (objI5 == v) {
                    objI5 = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(0);
                    c0814p2.i0(objI5);
                }
                function014 = (Function0) objI5;
                c0814p2.p(false);
            } else {
                function014 = function010;
            }
            if (c4716l.e) {
                c0814p2.X(2019896333);
                int i14 = i7 & 524286;
                Function0 function023 = function011;
                Function0 function024 = function012;
                e(c4716l, function023, function024, function08, function013, function014, c0814p2, i14);
                c0814p2.p(false);
                function015 = function023;
                function016 = function024;
                function017 = function08;
            } else {
                c0814p2.X(2020120277);
                int i15 = i7 & 524286;
                function015 = function011;
                function016 = function012;
                function017 = function08;
                c(c4716l, function015, function016, function017, function013, function014, c0814p2, i15);
                c0814p2.p(false);
            }
            c0814p = c0814p2;
            function018 = function014;
            function019 = function013;
            function020 = function017;
            function021 = function016;
            function022 = function015;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.c(c4716l, function022, function021, function020, function019, function018, i, i2);
        }
    }

    public static final void c(C4716l c4716l, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function0 function06;
        C4716l c4716l2 = c4716l;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1694803822);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(c4716l2) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            function06 = function02;
            i2 |= c0814p.h(function06) ? 256 : 128;
        } else {
            function06 = function02;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function03) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function04) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function05) ? 131072 : 65536;
        }
        if ((i2 & 74899) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarU = AbstractC0382e.u(nVar, f);
            c0814p.X(-169662578);
            int i3 = androidx.compose.material3.I.a;
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            androidx.compose.foundation.layout.S0 s0E = C0380d.e(c0814p);
            int i4 = AbstractC0382e.g;
            C0374a c0374a = new C0374a(new C0416v0(s0E.g, 32 | i4), new C0416v0(C0380d.e(c0814p).k, i4));
            c0814p.p(false);
            androidx.compose.ui.q qVarB = androidx.compose.foundation.layout.U0.b(qVarU, c0374a);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarB);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            mVar.c();
            float f2 = com.quizlet.ui.resources.designsystem.generated.f.h;
            com.quizlet.assembly.compose.buttons.A a = new com.quizlet.assembly.compose.buttons.A(function06, c4716l2, function03, function0, 20);
            c4716l2 = c4716l2;
            a(null, f2, androidx.compose.runtime.internal.e.e(-891627704, a, c0814p), c0814p, 384, 1);
            mVar.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            mVar.c();
            a(qVarY, f2, androidx.compose.runtime.internal.e.e(123063729, new com.quizlet.assembly.compose.menu.l(c4716l2, function04, function05, 28), c0814p), c0814p, 384, 0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.c(c4716l2, function0, function02, function03, function04, function05, i, 1, (byte) 0);
        }
    }

    public static final void d(C4739h c4739h, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1139430630);
        if ((((c0814p.h(c4739h) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            C4716l c4716l = (C4716l) C0776c.m(new kotlinx.coroutines.flow.Z(c4739h.i), c0814p).getValue();
            c0814p.X(1427575451);
            boolean zH = c0814p.h(c4739h);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zH || objI == v) {
                com.quizlet.features.flashcards.navigation.c cVar = new com.quizlet.features.flashcards.navigation.c(0, c4739h, C4739h.class, "navigateToUploadNotes", "navigateToUploadNotes(Z)V", 0, 29);
                c0814p.i0(cVar);
                objI = cVar;
            }
            Function0 function0 = (Function0) objI;
            c0814p.p(false);
            c0814p.X(1427577472);
            boolean zH2 = c0814p.h(c4739h);
            Object objI2 = c0814p.I();
            if (zH2 || objI2 == v) {
                com.quizlet.quizletandroid.ui.globalnav.composable.n nVar = new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, c4739h, C4739h.class, "navigateToCreateFlashcards", "navigateToCreateFlashcards()V", 0, 21);
                c0814p.i0(nVar);
                objI2 = nVar;
            }
            kotlin.reflect.f fVar = (kotlin.reflect.f) objI2;
            c0814p.p(false);
            c0814p.X(1427579483);
            boolean zH3 = c0814p.h(c4739h);
            Object objI3 = c0814p.I();
            if (zH3 || objI3 == v) {
                com.quizlet.quizletandroid.ui.globalnav.composable.n nVar2 = new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, c4739h, C4739h.class, "navigateToCreateClass", "navigateToCreateClass()V", 0, 22);
                c0814p.i0(nVar2);
                objI3 = nVar2;
            }
            kotlin.reflect.f fVar2 = (kotlin.reflect.f) objI3;
            c0814p.p(false);
            c0814p.X(1427581372);
            boolean zH4 = c0814p.h(c4739h);
            Object objI4 = c0814p.I();
            if (zH4 || objI4 == v) {
                com.quizlet.quizletandroid.ui.globalnav.composable.n nVar3 = new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, c4739h, C4739h.class, "navigateToCreateFolder", "navigateToCreateFolder()V", 0, 23);
                c0814p.i0(nVar3);
                objI4 = nVar3;
            }
            kotlin.reflect.f fVar3 = (kotlin.reflect.f) objI4;
            c0814p.p(false);
            c0814p.X(1427583490);
            boolean zH5 = c0814p.h(c4739h);
            Object objI5 = c0814p.I();
            if (zH5 || objI5 == v) {
                com.quizlet.quizletandroid.ui.globalnav.composable.n nVar4 = new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, c4739h, C4739h.class, "navigateToCreatePracticeTest", "navigateToCreatePracticeTest()V", 0, 24);
                c0814p.i0(nVar4);
                objI5 = nVar4;
            }
            c0814p.p(false);
            b(c4716l, (Function0) ((kotlin.reflect.f) objI5), (Function0) fVar, function0, (Function0) fVar3, (Function0) fVar2, c0814p, 0, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(c4739h, i, 10);
        }
    }

    public static final void e(C4716l c4716l, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1263925439);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(c4716l) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function02) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function03) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function04) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function05) ? 131072 : 65536;
        }
        if ((i2 & 74899) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarU = AbstractC0382e.u(nVar, f);
            c0814p.X(-169662578);
            int i3 = androidx.compose.material3.I.a;
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            androidx.compose.foundation.layout.S0 s0E = C0380d.e(c0814p);
            int i4 = AbstractC0382e.g;
            C0374a c0374a = new C0374a(new C0416v0(s0E.g, i4 | 32), new C0416v0(C0380d.e(c0814p).k, i4));
            c0814p.p(false);
            androidx.compose.ui.q qVarB = androidx.compose.foundation.layout.U0.b(qVarU, c0374a);
            C0380d c0380d = AbstractC0398m.a;
            mVar.s();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(f), androidx.compose.ui.b.m, c0814p, 0);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarB);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, R.string.creation_menu_title);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).f;
            long jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            mVar.u();
            androidx.compose.material3.Q4.b(strD, AbstractC0382e.y(qVarC2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, 7), jE, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65016);
            c0814p = c0814p;
            a(null, DefinitionKt.NO_Float_VALUE, androidx.compose.runtime.internal.e.e(1305718425, new com.quizlet.explanations.questiondetail.ui.composables.m(27, function02), c0814p), c0814p, 384, 3);
            c0814p.X(-1349497518);
            if (c4716l.b) {
                a(null, DefinitionKt.NO_Float_VALUE, androidx.compose.runtime.internal.e.e(117120350, new com.quizlet.explanations.questiondetail.ui.composables.m(28, function03), c0814p), c0814p, 384, 3);
            }
            c0814p.p(false);
            c0814p.X(-1349483763);
            if (c4716l.d) {
                a(null, DefinitionKt.NO_Float_VALUE, androidx.compose.runtime.internal.e.e(269548935, new com.quizlet.explanations.questiondetail.ui.composables.m(29, function0), c0814p), c0814p, 384, 3);
            }
            int i6 = 0;
            c0814p.p(false);
            c0814p.X(-1349469209);
            if (c4716l.c) {
                a(null, DefinitionKt.NO_Float_VALUE, androidx.compose.runtime.internal.e.e(519650214, new com.quizlet.quizletandroid.ui.startpage.nav2.composables.d(i6, function04), c0814p), c0814p, 384, 3);
            }
            c0814p.p(false);
            c0814p.X(-1349455837);
            if (c4716l.a) {
                a(null, DefinitionKt.NO_Float_VALUE, androidx.compose.runtime.internal.e.e(769751493, new com.quizlet.quizletandroid.ui.startpage.nav2.composables.d(1, function05), c0814p), c0814p, 384, 3);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.c(c4716l, function0, function02, function03, function04, function05, i, 2, (byte) 0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0055  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x005b  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0081  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x008c  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00c5  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00ea  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0174  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x01d0  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x01e0  */
    /* JADX WARN: Removed duplicated region for block: B:73:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void f(java.lang.String r30, androidx.compose.ui.graphics.painter.b r31, kotlin.jvm.functions.Function0 r32, androidx.compose.ui.n r33, boolean r34, androidx.compose.ui.graphics.C0853m r35, androidx.compose.runtime.InterfaceC0806l r36, int r37, int r38) {
        /*
            Method dump skipped, instructions count: 494
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.Y5.f(java.lang.String, androidx.compose.ui.graphics.painter.b, kotlin.jvm.functions.Function0, androidx.compose.ui.n, boolean, androidx.compose.ui.graphics.m, androidx.compose.runtime.l, int, int):void");
    }

    public static final void g(String str, String str2, androidx.compose.ui.graphics.painter.b bVar, Function0 function0, androidx.compose.ui.n nVar, String str3, InterfaceC0806l interfaceC0806l, int i, int i2) {
        String str4;
        int i3;
        androidx.compose.ui.n nVar2;
        String str5;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(384988969);
        int i4 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(str2) ? 32 : 16) | (c0814p.h(bVar) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024);
        int i5 = i4 | 24576;
        int i6 = i2 & 32;
        if (i6 != 0) {
            i3 = i4 | 221184;
            str4 = str3;
        } else {
            str4 = str3;
            i3 = i5 | (c0814p.f(str4) ? 131072 : 65536);
        }
        if ((74899 & i3) == 74898 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
            str5 = str4;
        } else {
            nVar2 = androidx.compose.ui.n.b;
            if (i6 != 0) {
                str4 = null;
            }
            String str6 = str4;
            int i7 = (i3 >> 6) & 14;
            int i8 = i3 << 3;
            C5.c(bVar, str, str2, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).a1, function0, str6, c0814p, i7 | (i8 & ContentType.LONG_FORM_ON_DEMAND) | (i8 & 896) | (57344 & i8) | 196608 | (i8 & 3670016));
            str5 = str6;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.screens.a(str, str2, bVar, function0, nVar2, str5, i, i2);
        }
    }

    public static final com.quizlet.assembly.compose.modals.x h(boolean z, boolean z2, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3 = 4;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-711915964);
        boolean z3 = true;
        boolean z4 = false;
        if ((i2 & 1) != 0) {
            z = false;
        }
        if ((i2 & 2) != 0) {
            z2 = false;
        }
        boolean z5 = (i2 & 4) == 0;
        c0814p.U(-234678150, Boolean.valueOf(z2));
        Object[] objArr = {Boolean.valueOf(z2), Boolean.valueOf(z), Boolean.valueOf(z5)};
        androidx.navigation.compose.x xVar = new androidx.navigation.compose.x(i3);
        com.quizlet.assembly.compose.modals.g gVar = new com.quizlet.assembly.compose.modals.g(z, z5);
        com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.runtime.saveable.m.a;
        com.quizlet.data.repository.explanations.myexplanations.a aVar2 = new com.quizlet.data.repository.explanations.myexplanations.a(xVar, z4, gVar, 3);
        c0814p.X(-234672076);
        boolean z6 = ((((i & 14) ^ 6) > 4 && c0814p.g(z)) || (i & 6) == 4) | ((((i & ContentType.LONG_FORM_ON_DEMAND) ^ 48) > 32 && c0814p.g(z2)) || (i & 48) == 32);
        if ((((i & 896) ^ 384) <= 256 || !c0814p.g(z5)) && (i & 384) != 256) {
            z3 = false;
        }
        boolean z7 = z3 | z6;
        Object objI = c0814p.I();
        if (z7 || objI == C0804k.a) {
            objI = new com.braze.storage.E(z2, z, z5);
            c0814p.i0(objI);
        }
        c0814p.p(false);
        com.quizlet.assembly.compose.modals.x xVar2 = (com.quizlet.assembly.compose.modals.x) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, aVar2, (Function0) objI, c0814p, 0, 4);
        c0814p.p(false);
        c0814p.p(false);
        return xVar2;
    }
}
