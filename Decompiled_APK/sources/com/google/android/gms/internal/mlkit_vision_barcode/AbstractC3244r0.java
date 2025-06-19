package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.material.AbstractC0579w;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0811n0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.text.C0995g;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3244r0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3578a5;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.assembly.compose.buttons.C4078c;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.r0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3244r0 {
    public static final void a(final boolean z, final boolean z2, final com.quizlet.features.flashcards.data.m onboarding, final androidx.compose.ui.q qVar, final Function0 function0, final Function0 function02, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        androidx.compose.ui.graphics.painter.b bVarE;
        long jA;
        C0814p c0814p;
        com.quizlet.features.flashcards.helpers.a aVar;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1316542212);
        if ((i & 6) == 0) {
            i2 = (c0814p2.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.g(z2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(onboarding) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.f(qVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(function0) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.h(function02) ? 131072 : 65536;
        }
        if ((74899 & i2) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            C0386g c0386g = AbstractC0398m.g;
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(c0386g, hVar, c0814p2, 54);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarC);
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
            com.quizlet.themes.e.a(c0814p2).a.getClass();
            c0814p2.X(-1759834226);
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_sys_undo, c0814p2, 0);
            c0814p2.p(false);
            String strD = AbstractC3106b5.d(c0814p2, R.string.flashcards_content_description_undo);
            C4076a c4076a = C4076a.e;
            int i4 = i2 >> 3;
            AbstractC3578a5.a(bVarA, strD, null, function0, z, c4076a, null, 0L, c0814p2, (i4 & 7168) | ((i2 << 12) & 57344), 196);
            c0814p2.X(840946316);
            if (onboarding != null) {
                Intrinsics.checkNotNullParameter(onboarding, "onboarding");
                c0814p2.X(758311856);
                switch (onboarding.ordinal()) {
                    case 0:
                        c0814p2.X(624025860);
                        c0814p2.X(1745633691);
                        aVar = new com.quizlet.features.flashcards.helpers.a(AbstractC3155h0.c(c0814p2, R.string.flashcards_onboarding_flip), null, null);
                        c0814p2.p(false);
                        c0814p2.p(false);
                        break;
                    case 1:
                        c0814p2.X(624028109);
                        c0814p2.X(1637049646);
                        aVar = new com.quizlet.features.flashcards.helpers.a(AbstractC3155h0.c(c0814p2, R.string.flashcards_onboarding_still_learning), null, null);
                        c0814p2.p(false);
                        c0814p2.p(false);
                        break;
                    case 2:
                        c0814p2.X(624030308);
                        c0814p2.X(167868989);
                        aVar = new com.quizlet.features.flashcards.helpers.a(AbstractC3155h0.c(c0814p2, R.string.flashcards_onboarding_know), null, null);
                        c0814p2.p(false);
                        c0814p2.p(false);
                        break;
                    case 3:
                        c0814p2.X(624032261);
                        c0814p2.X(2038225242);
                        aVar = new com.quizlet.features.flashcards.helpers.a(AbstractC3155h0.c(c0814p2, R.string.flashcards_onboarding_swipe), null, null);
                        c0814p2.p(false);
                        c0814p2.p(false);
                        break;
                    case 4:
                        c0814p2.X(624034212);
                        c0814p2.X(-149914236);
                        C0995g c0995gC = AbstractC3155h0.c(c0814p2, R.string.flashcards_onboarding_undo);
                        ((com.quizlet.themes.d) c0814p2.j(com.quizlet.themes.e.a)).a.getClass();
                        c0814p2.X(-1759834226);
                        androidx.compose.ui.graphics.painter.b bVarA2 = Z4.a(R.drawable.ic_sys_undo, c0814p2, 0);
                        c0814p2.p(false);
                        com.quizlet.features.flashcards.helpers.a aVar2 = new com.quizlet.features.flashcards.helpers.a(c0995gC, bVarA2, AbstractC3106b5.d(c0814p2, R.string.flashcards_content_description_undo));
                        c0814p2.p(false);
                        c0814p2.p(false);
                        aVar = aVar2;
                        break;
                    case 5:
                        c0814p2.X(624036264);
                        c0814p2.X(-1064053083);
                        C0995g c0995gC2 = AbstractC3155h0.c(c0814p2, R.string.flashcards_onboarding_settings);
                        ((com.quizlet.themes.d) c0814p2.j(com.quizlet.themes.e.a)).a.getClass();
                        aVar = new com.quizlet.features.flashcards.helpers.a(c0995gC2, com.quizlet.ui.resources.icons.d.J(c0814p2), AbstractC3106b5.d(c0814p2, R.string.flashcards_settings_content_description));
                        c0814p2.p(false);
                        c0814p2.p(false);
                        break;
                    case 6:
                        c0814p2.X(624038570);
                        c0814p2.X(2126748390);
                        C0995g c0995gC3 = AbstractC3155h0.c(c0814p2, R.string.flashcards_onboarding_auto_play_on);
                        ((com.quizlet.themes.d) c0814p2.j(com.quizlet.themes.e.a)).a.getClass();
                        aVar = new com.quizlet.features.flashcards.helpers.a(c0995gC3, com.quizlet.ui.resources.icons.d.E(c0814p2), AbstractC3106b5.d(c0814p2, R.string.flashcards_content_description_auto_play));
                        c0814p2.p(false);
                        c0814p2.p(false);
                        break;
                    case 7:
                        c0814p2.X(624040971);
                        c0814p2.X(786343528);
                        C0995g c0995gC4 = AbstractC3155h0.c(c0814p2, R.string.flashcards_onboarding_auto_play_off);
                        ((com.quizlet.themes.d) c0814p2.j(com.quizlet.themes.e.a)).a.getClass();
                        aVar = new com.quizlet.features.flashcards.helpers.a(c0995gC4, com.quizlet.ui.resources.icons.d.E(c0814p2), AbstractC3106b5.d(c0814p2, R.string.flashcards_content_description_stop_auto_play));
                        c0814p2.p(false);
                        c0814p2.p(false);
                        break;
                    default:
                        throw com.google.android.gms.measurement.internal.Z.j(624024698, c0814p2, false);
                }
                c0814p2.p(false);
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                AbstractC3269u0.a(aVar, androidx.compose.foundation.layout.K0.o(nVar, ((com.quizlet.themes.j) c0814p2.j(com.quizlet.themes.l.a)).g()), c0814p2, 0);
            }
            c0814p2.p(false);
            if (z2) {
                c0814p2.X(840960674);
                com.quizlet.themes.e.a(c0814p2).a.getClass();
                c0814p2.X(1201883518);
                bVarE = com.google.android.gms.measurement.internal.Z.d(R.drawable.ic_sys_pause, c0814p2, 0, false, false);
            } else {
                c0814p2.X(840961665);
                com.quizlet.themes.e.a(c0814p2).a.getClass();
                bVarE = com.quizlet.ui.resources.icons.d.E(c0814p2);
                c0814p2.p(false);
            }
            String strH = z2 ? com.google.android.gms.measurement.internal.Z.h(c0814p2, 300074367, R.string.flashcards_content_description_stop_auto_play, c0814p2, false) : com.google.android.gms.measurement.internal.Z.h(c0814p2, 300181348, R.string.flashcards_content_description_auto_play, c0814p2, false);
            if (z2) {
                c0814p2.X(300473957);
                jA = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).w;
                c0814p2.p(false);
            } else {
                c0814p2.X(300574428);
                jA = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).A();
                c0814p2.p(false);
            }
            long j = jA;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            com.google.android.gms.internal.mlkit_vision_document_scanner.V4.a(bVarE, strH, new C4078c(j, ((com.quizlet.themes.b) c0814p2.j(b)).b.f(), ((com.quizlet.themes.b) c0814p2.j(b)).A(), ((com.quizlet.themes.b) c0814p2.j(b)).b.b(), ((com.quizlet.themes.b) c0814p2.j(b)).t, 32), null, function02, false, c4076a, null, null, c0814p2, i4 & 57344, 936);
            c0814p = c0814p2;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.flashcards.views.composables.a
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    Function0 function03 = function0;
                    Function0 function04 = function02;
                    AbstractC3244r0.a(z, z2, onboarding, qVar, function03, function04, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void b(com.quizlet.search.data.b headerModel, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        Function1 function12 = function1;
        Intrinsics.checkNotNullParameter(headerModel, "headerModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-23453093);
        int i3 = i | (c0814p2.f(headerModel) ? 4 : 2) | (c0814p2.h(function12) ? 256 : 128);
        if ((i3 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p2, 0);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarC);
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
            androidx.compose.foundation.layout.I0 i0 = androidx.compose.foundation.layout.I0.a;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarA = i0.a(nVar, 1.0f, true);
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            androidx.compose.ui.q qVarB = i0.b(qVarA, hVar);
            int iOrdinal = headerModel.a.ordinal();
            if (iOrdinal == 0) {
                i2 = R.string.sets_header_title;
            } else if (iOrdinal == 1) {
                i2 = R.string.textbooks_header_title;
            } else if (iOrdinal == 2) {
                i2 = R.string.questions_header_title;
            } else if (iOrdinal == 3) {
                i2 = R.string.users_header_title;
            } else if (iOrdinal == 4) {
                i2 = R.string.classes_header_title;
            } else {
                if (iOrdinal != 5) {
                    throw new NoWhenBranchMatchedException();
                }
                i2 = R.string.terms_header_title;
            }
            String strD = AbstractC3106b5.d(c0814p2, i2);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(b)).f;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(strD, qVarB, ((com.quizlet.themes.b) c0814p2.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 1, 0, null, l, c0814p2, 0, 3072, 57336);
            c0814p = c0814p2;
            c0814p.X(-1948266118);
            if (headerModel.b) {
                androidx.compose.ui.q qVarB2 = i0.b(nVar, hVar);
                c0814p.X(-1948260803);
                boolean z = ((i3 & 14) == 4) | ((i3 & 896) == 256);
                Object objI = c0814p.I();
                if (z || objI == v) {
                    function12 = function1;
                    objI = new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v(5, function12, headerModel);
                    c0814p.i0(objI);
                } else {
                    function12 = function1;
                }
                c0814p.p(false);
                androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.view_all), AbstractC0460p.l(qVarB2, false, null, (Function0) objI, 7), ((com.quizlet.themes.b) c0814p.j(b2)).e, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).k, c0814p, 0, 0, 65528);
                c0814p = c0814p;
            } else {
                function12 = function1;
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(i, 13, headerModel, qVar, function12);
        }
    }

    public static final void c(androidx.compose.ui.q qVar, androidx.compose.ui.graphics.V v, long j, long j2, float f, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1412203386);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(v) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.e(j) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.e(j2) ? 2048 : 1024;
        }
        int i3 = i2 | 24576;
        if ((196608 & i) == 0) {
            i3 |= c0814p.c(f) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i3 |= c0814p.h(dVar) ? 1048576 : 524288;
        }
        if (c0814p.N(i3 & 1, (599187 & i3) != 599186)) {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            androidx.compose.runtime.B b = androidx.compose.material.A.b;
            float f2 = ((androidx.compose.ui.unit.e) c0814p.j(b)).a + f;
            C0776c.b(new C0811n0[]{androidx.compose.animation.d0.j(j2, AbstractC0579w.a), b.a(new androidx.compose.ui.unit.e(f2))}, androidx.compose.runtime.internal.e.e(-1822160838, new androidx.compose.material.h0(qVar, v, j, f2, f, dVar), c0814p), c0814p, 56);
        } else {
            c0814p.Q();
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.material.i0(qVar, v, j, j2, f, dVar, i);
        }
    }
}
