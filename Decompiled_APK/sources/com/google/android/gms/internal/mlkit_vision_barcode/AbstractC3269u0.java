package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.vector.C0867f;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.C0958o;
import androidx.compose.ui.platform.C0960p;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import androidx.lifecycle.InterfaceC1261w;
import androidx.navigation.compose.C1280m;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3269u0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.u0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3269u0 {
    public static C0867f a;

    public static final void a(com.quizlet.features.flashcards.helpers.a flashcardsOnboardingInfo, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2 = qVar;
        Intrinsics.checkNotNullParameter(flashcardsOnboardingInfo, "flashcardsOnboardingInfo");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1996948194);
        int i2 = i | (c0814p.h(flashcardsOnboardingInfo) ? 4 : 2) | (c0814p.f(qVar2) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.graphics.painter.b bVar = flashcardsOnboardingInfo.b;
            if (bVar != null) {
                c0814p.X(-1326733632);
                b(flashcardsOnboardingInfo.a, bVar, flashcardsOnboardingInfo.c, qVar, c0814p, (i2 << 6) & 7168);
                c0814p.p(false);
                qVar2 = qVar;
            } else {
                c0814p.X(-1326444464);
                qVar2 = qVar;
                androidx.compose.material3.Q4.c(flashcardsOnboardingInfo.a, qVar2, 0L, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).p, c0814p, i2 & ContentType.LONG_FORM_ON_DEMAND, 0, 130556);
                c0814p = c0814p;
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(flashcardsOnboardingInfo, qVar2, i, 14);
        }
    }

    public static final void b(C0995g c0995g, androidx.compose.ui.graphics.painter.b bVar, String str, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1988734078);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(c0995g) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(bVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(str) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.f(qVar) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            int iM = StringsKt.M(c0995g, "%1$s", 0, false, 6);
            C0995g c0995gSubSequence = c0995g.subSequence(0, iM);
            C0995g c0995gSubSequence2 = c0995g.subSequence(iM + 4, c0995g.a.length());
            C0984d c0984d = new C0984d();
            c0984d.d(c0995gSubSequence);
            AbstractC0484d0.p(c0984d, "iconId");
            c0984d.d(c0995gSubSequence2);
            C0995g c0995gJ = c0984d.j();
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            c0814p = c0814p2;
            androidx.compose.material3.Q4.c(c0995gJ, androidx.compose.ui.platform.N.G(qVar, "flashcards_onboarding_text_with_icon"), 0L, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, kotlin.collections.U.b(new Pair("iconId", new androidx.compose.foundation.text.Z(new androidx.compose.ui.text.v(((com.quizlet.themes.f) c0814p2.j(b)).p.a.b, ((com.quizlet.themes.f) c0814p2.j(b)).p.a.b, 4), androidx.compose.runtime.internal.e.e(1979103712, new com.quizlet.assembly.compose.input.m(8, bVar, str), c0814p2)))), null, ((com.quizlet.themes.f) c0814p2.j(b)).p, c0814p, 0, 0, 97788);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i((Object) c0995g, (Object) bVar, (Object) str, qVar, i, 7);
        }
    }

    public static final void c(final com.quizlet.search.data.j jVar, final androidx.compose.ui.q qVar, final boolean z, final androidx.compose.ui.focus.h hVar, com.quizlet.search.viewmodels.A a2, final Function1 function1, final Function0 function0, final Function0 function02, final Function1 function12, final kotlin.jvm.functions.c cVar, final Function2 function2, final Function2 function22, final kotlin.jvm.functions.c cVar2, final kotlin.jvm.functions.c cVar3, final Function2 function23, final Function1 function13, final kotlin.jvm.functions.c cVar4, final Function1 function14, final Function1 function15, final Function0 function03, final Function0 function04, final Function2 function24, com.quizlet.assembly.compose.modals.x xVar, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        boolean z2;
        boolean z3;
        com.quizlet.search.viewmodels.A a3;
        int i3;
        com.quizlet.assembly.compose.modals.x xVarH;
        final com.quizlet.search.viewmodels.A a4;
        final com.quizlet.assembly.compose.modals.x xVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1730709954);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(jVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(hVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function1) ? 131072 : 65536;
        }
        if ((i & 1572864) == 0) {
            i2 |= c0814p.h(function0) ? 1048576 : 524288;
        }
        if ((i & 12582912) == 0) {
            i2 |= c0814p.h(function02) ? 8388608 : 4194304;
        }
        if ((i & 100663296) == 0) {
            i2 |= c0814p.h(function12) ? 67108864 : 33554432;
        }
        if ((i & 805306368) == 0) {
            z2 = true;
            i2 |= c0814p.h(cVar) ? 536870912 : 268435456;
        } else {
            z2 = true;
        }
        int i4 = i2;
        int i5 = (c0814p.h(function2) ? (char) 4 : (char) 2) | (c0814p.h(function22) ? ' ' : (char) 16) | (c0814p.h(cVar2) ? 256 : 128) | (c0814p.h(cVar3) ? (char) 2048 : (char) 1024) | (c0814p.h(function23) ? 16384 : 8192) | (c0814p.h(function13) ? (char) 0 : (char) 0) | (c0814p.h(cVar4) ? (char) 0 : (char) 0) | (c0814p.h(function14) ? (char) 0 : (char) 0) | (c0814p.h(function15) ? (char) 0 : (char) 0) | (c0814p.h(function03) ? (char) 0 : (char) 0);
        int i6 = (c0814p.h(function04) ? (char) 4 : (char) 2) | (c0814p.h(function24) ? ' ' : (char) 16) | 128;
        if ((i4 & 306783379) == 306783378 && (i5 & 306783379) == 306783378 && (i6 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            a4 = a2;
            xVar2 = xVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                z3 = false;
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(com.quizlet.search.viewmodels.A.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                a3 = (com.quizlet.search.viewmodels.A) w0VarE;
                i3 = i4 & (-57345);
                xVarH = com.google.android.gms.internal.mlkit_vision_document_scanner.Y5.h(z2, false, c0814p, 6, 6);
            } else {
                c0814p.Q();
                a3 = a2;
                xVarH = xVar;
                i3 = i4 & (-57345);
                z3 = false;
            }
            c0814p.q();
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-1315346174, new com.quizlet.search.composables.y(hVar, z, jVar, function1, function0, function02, function12), c0814p);
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(z3);
            com.quizlet.search.viewmodels.A a5 = a3;
            com.quizlet.assembly.compose.modals.x xVar3 = xVarH;
            AbstractC0725t3.a(qVar, dVarE, null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(1822581325, new com.quizlet.search.composables.z(jVar, function04, xVar3, a5, cVar, function2, function22, cVar2, cVar3, function23, function13, cVar4, function24, function15, hVar, function14, function03), c0814p), c0814p, ((i3 >> 3) & 14) | 805306416, 188);
            c0814p = c0814p;
            AbstractC3277v0.j(xVar3, a5, c0814p, 8);
            a4 = a5;
            xVar2 = xVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.search.composables.x
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    Function2 function25 = function24;
                    com.quizlet.assembly.compose.modals.x xVar4 = xVar2;
                    AbstractC3269u0.c(jVar, qVar, z, hVar, a4, function1, function0, function02, function12, cVar, function2, function22, cVar2, cVar3, function23, function13, cVar4, function14, function15, function03, function04, function25, xVar4, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void d(com.quizlet.search.viewmodels.p viewModel, androidx.compose.ui.q qVar, boolean z, androidx.compose.ui.focus.h hVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.focus.h hVar2;
        boolean z2;
        C0814p c0814p;
        androidx.compose.ui.focus.h hVar3;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1229343515);
        int i3 = i | (c0814p2.h(viewModel) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.g(z) ? 256 : 128) | 1024;
        if ((i3 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            hVar3 = hVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                i2 = i3 & (-7169);
                hVar2 = (androidx.compose.ui.focus.h) c0814p2.j(AbstractC0955m0.g);
            } else {
                c0814p2.Q();
                i2 = i3 & (-7169);
                hVar2 = hVar;
            }
            int i4 = i2;
            c0814p2.q();
            com.quizlet.search.data.j jVar = (com.quizlet.search.data.j) C0776c.m(new kotlinx.coroutines.flow.Z(viewModel.i), c0814p2).getValue();
            c0814p2.X(-94870838);
            boolean zH = c0814p2.h(viewModel);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zH || objI == v) {
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y(1, viewModel, com.quizlet.search.viewmodels.p.class, "onSearchTextChange", "onSearchTextChange(Ljava/lang/String;)V", 0, 24);
                c0814p2.i0(yVar);
                objI = yVar;
            }
            kotlin.reflect.f fVar = (kotlin.reflect.f) objI;
            c0814p2.p(false);
            c0814p2.X(-94869149);
            boolean zH2 = c0814p2.h(viewModel);
            Object objI2 = c0814p2.I();
            if (zH2 || objI2 == v) {
                z2 = false;
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l lVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, viewModel, com.quizlet.search.viewmodels.p.class, "onBackClick", "onBackClick()V", 0, 25);
                c0814p2.i0(lVar);
                objI2 = lVar;
            } else {
                z2 = false;
            }
            kotlin.reflect.f fVar2 = (kotlin.reflect.f) objI2;
            c0814p2.p(z2);
            c0814p2.X(-94867644);
            boolean zH3 = c0814p2.h(viewModel);
            Object objI3 = c0814p2.I();
            if (zH3 || objI3 == v) {
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l lVar2 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, viewModel, com.quizlet.search.viewmodels.p.class, "onQueryClear", "onQueryClear()V", 0, 26);
                c0814p2.i0(lVar2);
                objI3 = lVar2;
            }
            kotlin.reflect.f fVar3 = (kotlin.reflect.f) objI3;
            c0814p2.p(z2);
            c0814p2.X(-94866039);
            boolean zH4 = c0814p2.h(viewModel);
            Object objI4 = c0814p2.I();
            if (zH4 || objI4 == v) {
                androidx.compose.ui.scrollcapture.k kVar = new androidx.compose.ui.scrollcapture.k(1, viewModel, com.quizlet.search.viewmodels.p.class, "onSearchSubmitted", "onSearchSubmitted(Ljava/lang/String;Z)V", 0, 5);
                c0814p2.i0(kVar);
                objI4 = kVar;
            }
            Function1 function1 = (Function1) objI4;
            c0814p2.p(z2);
            c0814p2.X(-94864246);
            boolean zH5 = c0814p2.h(viewModel);
            Object objI5 = c0814p2.I();
            if (zH5 || objI5 == v) {
                C0958o c0958o = new C0958o(3, viewModel, com.quizlet.search.viewmodels.p.class, "navigateToStudySet", "navigateToStudySet(JIZ)V", 0, 6);
                c0814p2.i0(c0958o);
                objI5 = c0958o;
            }
            kotlin.reflect.f fVar4 = (kotlin.reflect.f) objI5;
            c0814p2.p(z2);
            c0814p2.X(-94862422);
            boolean zH6 = c0814p2.h(viewModel);
            Object objI6 = c0814p2.I();
            if (zH6 || objI6 == v) {
                C0958o c0958o2 = new C0958o(3, viewModel, com.quizlet.search.viewmodels.p.class, "navigateToTextbook", "navigateToTextbook(JLjava/lang/String;I)V", 0, 7);
                c0814p2.i0(c0958o2);
                objI6 = c0958o2;
            }
            kotlin.reflect.f fVar5 = (kotlin.reflect.f) objI6;
            c0814p2.p(z2);
            c0814p2.X(-94860598);
            boolean zH7 = c0814p2.h(viewModel);
            Object objI7 = c0814p2.I();
            if (zH7 || objI7 == v) {
                C0958o c0958o3 = new C0958o(3, viewModel, com.quizlet.search.viewmodels.p.class, "navigateToQuestion", "navigateToQuestion(Ljava/lang/String;Ljava/lang/String;I)V", 0, 8);
                c0814p2.i0(c0958o3);
                objI7 = c0958o3;
            }
            kotlin.reflect.f fVar6 = (kotlin.reflect.f) objI7;
            c0814p2.p(z2);
            c0814p2.X(-94858873);
            boolean zH8 = c0814p2.h(viewModel);
            Object objI8 = c0814p2.I();
            if (zH8 || objI8 == v) {
                C0960p c0960p = new C0960p(2, viewModel, com.quizlet.search.viewmodels.p.class, "navigateToClass", "navigateToClass(JI)V", 0, 28);
                c0814p2.i0(c0960p);
                objI8 = c0960p;
            }
            kotlin.reflect.f fVar7 = (kotlin.reflect.f) objI8;
            c0814p2.p(z2);
            c0814p2.X(-94857274);
            boolean zH9 = c0814p2.h(viewModel);
            Object objI9 = c0814p2.I();
            if (zH9 || objI9 == v) {
                C0960p c0960p2 = new C0960p(2, viewModel, com.quizlet.search.viewmodels.p.class, "navigateToUser", "navigateToUser(JI)V", 0, 29);
                c0814p2.i0(c0960p2);
                objI9 = c0960p2;
            }
            kotlin.reflect.f fVar8 = (kotlin.reflect.f) objI9;
            c0814p2.p(z2);
            c0814p2.X(-94855707);
            boolean zH10 = c0814p2.h(viewModel);
            Object objI10 = c0814p2.I();
            if (zH10 || objI10 == v) {
                C0960p c0960p3 = new C0960p(2, viewModel, com.quizlet.search.viewmodels.p.class, "onTermClicked", "onTermClicked(Lcom/quizlet/search/data/term/TermSearchUiModel;I)V", 0, 26);
                c0814p2.i0(c0960p3);
                objI10 = c0960p3;
            }
            kotlin.reflect.f fVar9 = (kotlin.reflect.f) objI10;
            c0814p2.p(z2);
            c0814p2.X(-94853843);
            boolean zH11 = c0814p2.h(viewModel);
            Object objI11 = c0814p2.I();
            if (zH11 || objI11 == v) {
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar2 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y(1, viewModel, com.quizlet.search.viewmodels.p.class, "onSearchShortcutClick", "onSearchShortcutClick(Lcom/quizlet/ui/models/search/SearchShortcutUiModel;)V", 0, 25);
                c0814p2.i0(yVar2);
                objI11 = yVar2;
            }
            kotlin.reflect.f fVar10 = (kotlin.reflect.f) objI11;
            c0814p2.p(z2);
            c0814p2.X(-94851759);
            boolean zH12 = c0814p2.h(viewModel);
            Object objI12 = c0814p2.I();
            if (zH12 || objI12 == v) {
                C0958o c0958o4 = new C0958o(3, viewModel, com.quizlet.search.viewmodels.p.class, "navigateToStudySetPreview", "navigateToStudySetPreview(JLjava/util/List;I)V", 0, 5);
                c0814p2.i0(c0958o4);
                objI12 = c0958o4;
            }
            kotlin.reflect.f fVar11 = (kotlin.reflect.f) objI12;
            c0814p2.p(z2);
            c0814p2.X(-94849652);
            boolean zH13 = c0814p2.h(viewModel);
            Object objI13 = c0814p2.I();
            if (zH13 || objI13 == v) {
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar3 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y(1, viewModel, com.quizlet.search.viewmodels.p.class, "onSuggestionsClicked", "onSuggestionsClicked(Ljava/lang/String;)V", 0, 26);
                c0814p2.i0(yVar3);
                objI13 = yVar3;
            }
            kotlin.reflect.f fVar12 = (kotlin.reflect.f) objI13;
            c0814p2.p(z2);
            c0814p2.X(-94847800);
            boolean zH14 = c0814p2.h(viewModel);
            Object objI14 = c0814p2.I();
            if (zH14 || objI14 == v) {
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l lVar3 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, viewModel, com.quizlet.search.viewmodels.p.class, "onViewAllClicked", "onViewAllClicked()V", 0, 23);
                c0814p2.i0(lVar3);
                objI14 = lVar3;
            }
            kotlin.reflect.f fVar13 = (kotlin.reflect.f) objI14;
            c0814p2.p(z2);
            c0814p2.X(-94845840);
            boolean zH15 = c0814p2.h(viewModel);
            Object objI15 = c0814p2.I();
            if (zH15 || objI15 == v) {
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l lVar4 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, viewModel, com.quizlet.search.viewmodels.p.class, "onPlayQuizletLiveClicked", "onPlayQuizletLiveClicked()V", 0, 24);
                c0814p2.i0(lVar4);
                objI15 = lVar4;
            }
            kotlin.reflect.f fVar14 = (kotlin.reflect.f) objI15;
            c0814p2.p(z2);
            c0814p2.X(-94843930);
            boolean zH16 = c0814p2.h(viewModel);
            Object objI16 = c0814p2.I();
            if (zH16 || objI16 == v) {
                C0960p c0960p4 = new C0960p(2, viewModel, com.quizlet.search.viewmodels.p.class, "onPageSelected", "onPageSelected(Lcom/quizlet/eventlogger/features/search/SearchType;Ljava/util/List;)V", 0, 27);
                c0814p2.i0(c0960p4);
                objI16 = c0960p4;
            }
            kotlin.reflect.f fVar15 = (kotlin.reflect.f) objI16;
            c0814p2.p(z2);
            c0814p2.X(-94842099);
            boolean zH17 = c0814p2.h(viewModel);
            Object objI17 = c0814p2.I();
            if (zH17 || objI17 == v) {
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar4 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y(1, viewModel, com.quizlet.search.viewmodels.p.class, "onMisspellingsClicked", "onMisspellingsClicked(Lcom/quizlet/search/data/SearchMisspellingsData;)V", 0, 27);
                c0814p2.i0(yVar4);
                objI17 = yVar4;
            }
            c0814p2.p(z2);
            c0814p = c0814p2;
            hVar3 = hVar2;
            c(jVar, qVar, z, hVar3, null, (Function1) fVar, (Function0) fVar2, (Function0) fVar3, function1, (kotlin.jvm.functions.c) fVar4, (Function2) fVar7, (Function2) fVar8, (kotlin.jvm.functions.c) fVar5, (kotlin.jvm.functions.c) fVar6, (Function2) fVar9, (Function1) fVar10, (kotlin.jvm.functions.c) fVar11, (Function1) fVar12, (Function1) ((kotlin.reflect.f) objI17), (Function0) fVar13, (Function0) fVar14, (Function2) fVar15, null, c0814p, i4 & 8176);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.o(viewModel, qVar, z, hVar3, i, 8);
        }
    }

    public static final void e(androidx.compose.ui.focus.h hVar, boolean z, String str, Function1 function1, Function0 function0, Function0 function02, Function1 function12, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1664620249);
        if (((i | (c0814p2.h(hVar) ? 4 : 2) | (c0814p2.g(z) ? 32 : 16) | (c0814p2.f(str) ? 256 : 128) | (c0814p2.h(function1) ? 2048 : 1024) | (c0814p2.h(function0) ? 16384 : 8192) | (c0814p2.h(function02) ? 131072 : 65536) | (c0814p2.h(function12) ? 1048576 : 524288)) & 599187) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.s();
            c0814p = c0814p2;
            AbstractC3691o6.b(androidx.compose.runtime.internal.e.e(1194711415, new com.quizlet.features.infra.folder.create.composables.a(str, z, hVar, function1, function02, function12), c0814p2), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, 0L, null, androidx.compose.runtime.internal.e.e(-639095759, new com.quizlet.quizletandroid.ui.startpage.nav2.composables.d(6, function0), c0814p2), null, c0814p, 1572870, 184);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.k(hVar, z, str, function1, function0, function02, function12, i);
        }
    }
}
