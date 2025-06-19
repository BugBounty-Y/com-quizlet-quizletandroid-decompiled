package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.lazy.grid.C0426a;
import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import androidx.paging.C1319i;
import com.comscore.streaming.ContentType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3209n0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.features.flashcards.C4239m;
import com.quizlet.features.flashcards.C4242p;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.n0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3209n0 {
    public static final void a(com.quizlet.features.flashcards.settings.k kVar, Function1 function1, Function1 function12, Function1 function13, Function1 function14, Function1 function15, Function1 function16, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2009733646);
        if (((i | (c0814p.h(kVar) ? 4 : 2) | (c0814p.h(function1) ? 32 : 16) | (c0814p.h(function12) ? 256 : 128) | (c0814p.h(function13) ? 2048 : 1024) | (c0814p.h(function14) ? 16384 : 8192) | (c0814p.h(function15) ? 131072 : 65536) | (c0814p.h(function16) ? 1048576 : 524288) | (c0814p.h(function0) ? 8388608 : 4194304)) & 38347923) == 38347922 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.b(com.google.android.gms.internal.mlkit_vision_document_scanner.Y5.h(true, true, c0814p, 54, 4), null, false, null, null, function02, androidx.compose.runtime.internal.e.e(1261474227, new C4239m(kVar, function13, function14, function0, function1, function12, function15, function16), c0814p), c0814p, 1769480, 30);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.settings.ui.a(kVar, function1, function12, function13, function14, function15, function16, function0, function02, i, 0);
        }
    }

    public static final void b(Function0 navigateBack, com.quizlet.features.flashcards.S flashcardsViewModel, com.quizlet.features.flashcards.settings.l lVar, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.flashcards.settings.l lVar2;
        Function0 function0;
        com.quizlet.features.flashcards.settings.l lVar3;
        com.quizlet.features.flashcards.settings.l lVar4;
        int i2 = 0;
        Intrinsics.checkNotNullParameter(navigateBack, "navigateBack");
        Intrinsics.checkNotNullParameter(flashcardsViewModel, "flashcardsViewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1391648140);
        if (((i | (c0814p.h(navigateBack) ? 4 : 2) | (c0814p.h(flashcardsViewModel) ? 32 : 16) | 128) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            lVar4 = lVar;
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
                Object objE = AbstractC3417z1.e(com.quizlet.features.flashcards.settings.j.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                lVar2 = (com.quizlet.features.flashcards.settings.l) objE;
            } else {
                c0814p.Q();
                lVar2 = lVar;
            }
            c0814p.q();
            com.quizlet.features.flashcards.settings.j jVar = (com.quizlet.features.flashcards.settings.j) lVar2;
            kotlinx.coroutines.flow.s0 s0Var = jVar.m;
            androidx.lifecycle.viewmodel.internal.a scope = androidx.lifecycle.p0.j(jVar);
            com.quizlet.features.flashcards.settings.e transform = new com.quizlet.features.flashcards.settings.e(jVar, i2);
            Intrinsics.checkNotNullParameter(s0Var, "<this>");
            Intrinsics.checkNotNullParameter(scope, "scope");
            Intrinsics.checkNotNullParameter(transform, "transform");
            com.quizlet.features.flashcards.settings.g gVar = new com.quizlet.features.flashcards.settings.g(transform, null);
            int i3 = kotlinx.coroutines.flow.G.a;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(kotlinx.coroutines.flow.e0.x(new kotlinx.coroutines.flow.internal.m(new C1319i((Object) gVar, (kotlin.coroutines.h) null, 13), s0Var, kotlin.coroutines.n.a, -2, kotlinx.coroutines.channels.a.a), scope, kotlinx.coroutines.flow.h0.a, transform.invoke(s0Var.getValue())), c0814p);
            c0814p.X(1570164560);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = new com.quizlet.data.repository.explanations.exercise.a(10, flashcardsViewModel, navigateBack);
                c0814p.i0(objI);
            }
            Function0 function02 = (Function0) objI;
            c0814p.p(false);
            kotlinx.coroutines.flow.d0 d0Var = jVar.n;
            c0814p.X(1570170293);
            boolean zH = c0814p.h(flashcardsViewModel);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                objI2 = new com.quizlet.features.flashcards.settings.ui.d(flashcardsViewModel, function02, null);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI3 = c0814p.I();
            if (zF || objI3 == v) {
                objI3 = new com.quizlet.features.flashcards.settings.ui.c(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI3);
            c0814p.p(false);
            androidx.work.impl.t.a(false, function02, c0814p, 48, 1);
            com.quizlet.features.flashcards.settings.k kVar = (com.quizlet.features.flashcards.settings.k) interfaceC0773a0M.getValue();
            c0814p.X(-517334164);
            boolean zH2 = c0814p.h(lVar2);
            Object objI4 = c0814p.I();
            if (zH2 || objI4 == v) {
                function0 = function02;
                objI4 = new com.quizlet.explanations.textbook.ui.f(1, lVar2, com.quizlet.features.flashcards.settings.l.class, "onShufflePressed", "onShufflePressed(Z)V", 0, 12);
                c0814p.i0(objI4);
            } else {
                function0 = function02;
            }
            c0814p.p(false);
            Function1 function1 = (Function1) ((kotlin.reflect.f) objI4);
            c0814p.X(-517332334);
            boolean zH3 = c0814p.h(lVar2);
            Object objI5 = c0814p.I();
            if (zH3 || objI5 == v) {
                com.quizlet.explanations.textbook.ui.f fVar = new com.quizlet.explanations.textbook.ui.f(1, lVar2, com.quizlet.features.flashcards.settings.l.class, "onAudioPlaybackPressed", "onAudioPlaybackPressed(Z)V", 0, 13);
                c0814p.i0(fVar);
                objI5 = fVar;
            }
            c0814p.p(false);
            Function1 function12 = (Function1) ((kotlin.reflect.f) objI5);
            c0814p.X(-517330318);
            boolean zH4 = c0814p.h(lVar2);
            Object objI6 = c0814p.I();
            if (zH4 || objI6 == v) {
                com.quizlet.explanations.textbook.ui.f fVar2 = new com.quizlet.explanations.textbook.ui.f(1, lVar2, com.quizlet.features.flashcards.settings.l.class, "onFlashcardModeChanged", "onFlashcardModeChanged(Z)V", 0, 14);
                c0814p.i0(fVar2);
                objI6 = fVar2;
            }
            c0814p.p(false);
            Function1 function13 = (Function1) ((kotlin.reflect.f) objI6);
            c0814p.X(-517328434);
            boolean zH5 = c0814p.h(lVar2);
            Object objI7 = c0814p.I();
            if (zH5 || objI7 == v) {
                com.quizlet.explanations.textbook.ui.f fVar3 = new com.quizlet.explanations.textbook.ui.f(1, lVar2, com.quizlet.features.flashcards.settings.l.class, "onFrontSideChanged", "onFrontSideChanged(LassistantMode/enums/StudiableCardSideLabel;)V", 0, 15);
                c0814p.i0(fVar3);
                objI7 = fVar3;
            }
            c0814p.p(false);
            Function1 function14 = (Function1) ((kotlin.reflect.f) objI7);
            c0814p.X(-517326707);
            boolean zH6 = c0814p.h(lVar2);
            Object objI8 = c0814p.I();
            if (zH6 || objI8 == v) {
                com.quizlet.explanations.textbook.ui.f fVar4 = new com.quizlet.explanations.textbook.ui.f(1, lVar2, com.quizlet.features.flashcards.settings.l.class, "onBackSideChanged", "onBackSideChanged(LassistantMode/enums/StudiableCardSideLabel;)V", 0, 16);
                c0814p.i0(fVar4);
                objI8 = fVar4;
            }
            c0814p.p(false);
            Function1 function15 = (Function1) ((kotlin.reflect.f) objI8);
            c0814p.X(-517324945);
            boolean zH7 = c0814p.h(lVar2);
            Object objI9 = c0814p.I();
            if (zH7 || objI9 == v) {
                com.quizlet.explanations.textbook.ui.f fVar5 = new com.quizlet.explanations.textbook.ui.f(1, lVar2, com.quizlet.features.flashcards.settings.l.class, "onStudyUsingChanged", "onStudyUsingChanged(Z)V", 0, 17);
                c0814p.i0(fVar5);
                objI9 = fVar5;
            }
            c0814p.p(false);
            Function1 function16 = (Function1) ((kotlin.reflect.f) objI9);
            c0814p.X(-517322890);
            boolean zH8 = c0814p.h(lVar2);
            Object objI10 = c0814p.I();
            if (zH8 || objI10 == v) {
                C4242p c4242p = new C4242p(0, lVar2, com.quizlet.features.flashcards.settings.l.class, "onRestartFlashcardsPressed", "onRestartFlashcardsPressed()V", 0, 15);
                lVar3 = lVar2;
                c0814p.i0(c4242p);
                objI10 = c4242p;
            } else {
                lVar3 = lVar2;
            }
            c0814p.p(false);
            a(kVar, function1, function12, function13, function14, function15, function16, (Function0) ((kotlin.reflect.f) objI10), function0, c0814p, 100663296);
            lVar4 = lVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(navigateBack, flashcardsViewModel, lVar4, i, 17);
        }
    }

    public static final void c(final com.quizlet.search.data.blended.h hVar, final SearchType searchType, final kotlin.jvm.functions.c cVar, final Function2 function2, final Function2 function22, final kotlin.jvm.functions.c cVar2, final kotlin.jvm.functions.c cVar3, final Function2 function23, final Function1 function1, final Function1 function12, final Function1 function13, final androidx.compose.ui.n nVar, final float f, final androidx.compose.foundation.lazy.grid.A a, InterfaceC0806l interfaceC0806l, final int i, final int i2) {
        int i3;
        Function2 function24;
        Function2 function25;
        int i4;
        int i5;
        C0426a c0426a;
        int i6;
        androidx.compose.foundation.layout.A0 a0;
        boolean z;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-691772929);
        if ((i & 6) == 0) {
            i3 = (c0814p2.h(hVar) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p2.f(searchType) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p2.h(cVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            function24 = function2;
            i3 |= c0814p2.h(function24) ? 2048 : 1024;
        } else {
            function24 = function2;
        }
        if ((i & 24576) == 0) {
            function25 = function22;
            i3 |= c0814p2.h(function25) ? 16384 : 8192;
        } else {
            function25 = function22;
        }
        if ((i & 196608) == 0) {
            i3 |= c0814p2.h(cVar2) ? 131072 : 65536;
        }
        if ((i & 1572864) == 0) {
            i4 = i3 | (c0814p2.h(cVar3) ? 1048576 : 524288);
        } else {
            i4 = i3;
        }
        if ((i & 12582912) == 0) {
            i4 |= c0814p2.h(function23) ? 8388608 : 4194304;
        }
        if ((i & 100663296) == 0) {
            i4 |= c0814p2.h(function1) ? 67108864 : 33554432;
        }
        if ((i & 805306368) == 0) {
            i4 |= c0814p2.h(function12) ? 536870912 : 268435456;
        }
        int i7 = i4;
        if ((i2 & 6) == 0) {
            i5 = i2 | (c0814p2.h(function13) ? 4 : 2);
        } else {
            i5 = i2;
        }
        if ((i2 & 48) == 0) {
            i5 |= c0814p2.f(nVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i5 |= c0814p2.c(f) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i5 |= c0814p2.f(a) ? 2048 : 1024;
        }
        int i8 = i5;
        if ((i7 & 306783379) == 306783378 && (i8 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
        } else {
            c0814p2.S();
            if ((i & 1) != 0 && !c0814p2.w()) {
                c0814p2.Q();
            }
            c0814p2.q();
            final int iD = AbstractC3236q0.d(c0814p2);
            List list = hVar.a;
            if (list.size() == 1 && (CollectionsKt.L(list) instanceof com.quizlet.ui.models.search.b)) {
                c0814p2.X(-966230241);
                androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
                com.quizlet.themes.m.g.s();
                AbstractC3182k0.a(AbstractC0382e.y(AbstractC0382e.u(nVar2, com.quizlet.ui.resources.designsystem.generated.j.h), DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), c0814p2, 0);
                c0814p2.p(false);
            } else {
                c0814p2.X(-965905919);
                final com.quizlet.ui.compose.util.a aVar = new com.quizlet.ui.compose.util.a(searchType == SearchType.a, null, a, 2);
                C0426a c0426a2 = new C0426a(iD);
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.s();
                float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
                mVar.s();
                mVar.q();
                float f3 = com.quizlet.ui.resources.designsystem.generated.j.i;
                mVar.q();
                androidx.compose.foundation.layout.A0 a02 = new androidx.compose.foundation.layout.A0(f2, f3, f2, f3 + f);
                androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(nVar, 1.0f).g(androidx.compose.foundation.layout.K0.b), "allResultsList");
                C0380d c0380d = AbstractC0398m.a;
                mVar.s();
                C0392j c0392jG = AbstractC0398m.g(f2);
                mVar.s();
                C0392j c0392jG2 = AbstractC0398m.g(f2);
                c0814p2.X(523060951);
                boolean zH = c0814p2.h(hVar) | c0814p2.d(iD) | ((1879048192 & i7) == 536870912) | ((i7 & 896) == 256) | c0814p2.h(aVar) | ((i8 & 14) == 4) | ((458752 & i7) == 131072) | ((3670016 & i7) == 1048576) | ((57344 & i7) == 16384) | ((i7 & 7168) == 2048) | ((29360128 & i7) == 8388608) | ((234881024 & i7) == 67108864);
                Object objI = c0814p2.I();
                if (zH || objI == C0804k.a) {
                    c0426a = c0426a2;
                    i6 = i8;
                    final Function2 function26 = function24;
                    a0 = a02;
                    z = false;
                    c0814p = c0814p2;
                    final Function2 function27 = function25;
                    Function1 function14 = new Function1() { // from class: com.quizlet.search.composables.h
                        @Override // kotlin.jvm.functions.Function1
                        public final Object invoke(Object obj) {
                            androidx.compose.foundation.lazy.grid.i LazyVerticalGrid = (androidx.compose.foundation.lazy.grid.i) obj;
                            Intrinsics.checkNotNullParameter(LazyVerticalGrid, "$this$LazyVerticalGrid");
                            com.quizlet.search.data.blended.h hVar2 = hVar;
                            androidx.navigation.compose.x xVar = new androidx.navigation.compose.x(29);
                            C4791j c4791j = new C4791j(iD);
                            List list2 = hVar2.a;
                            LazyVerticalGrid.p(list2.size(), new androidx.compose.ui.viewinterop.b(24, xVar, list2), new androidx.compose.foundation.contextmenu.i(29, c4791j, list2), new com.quizlet.assembly.compose.menu.e(list2, 25), new androidx.compose.runtime.internal.d(true, 1229287273, new C4793l(list2, function12, cVar, aVar, function13, cVar2, cVar3, function27, function26, function23, function1)));
                            return Unit.a;
                        }
                    };
                    c0814p.i0(function14);
                    objI = function14;
                } else {
                    c0426a = c0426a2;
                    i6 = i8;
                    a0 = a02;
                    z = false;
                    c0814p = c0814p2;
                }
                c0814p.p(z);
                c0814p2 = c0814p;
                AbstractC3155h0.b(c0426a, qVarG, a, a0, c0392jG, c0392jG2, null, false, (Function1) objI, c0814p2, (i6 >> 3) & 896, 400);
                c0814p2.p(z);
            }
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.search.composables.i
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    int iH2 = C0776c.H(i2);
                    com.quizlet.search.data.blended.h hVar2 = hVar;
                    float f4 = f;
                    androidx.compose.foundation.lazy.grid.A a2 = a;
                    AbstractC3209n0.c(hVar2, searchType, cVar, function2, function22, cVar2, cVar3, function23, function1, function12, function13, nVar, f4, a2, (InterfaceC0806l) obj, iH, iH2);
                    return Unit.a;
                }
            };
        }
    }

    public static final void d(final String str, final SearchType searchType, androidx.compose.ui.n nVar, final float f, final com.quizlet.search.viewmodels.r rVar, final kotlin.jvm.functions.c cVar, final Function2 function2, final Function2 function22, final kotlin.jvm.functions.c cVar2, final kotlin.jvm.functions.c cVar3, final Function2 function23, final Function1 function1, final Function1 function12, InterfaceC0806l interfaceC0806l, final int i) {
        androidx.compose.ui.n nVar2;
        int i2;
        androidx.compose.ui.n nVar3;
        final androidx.compose.ui.n nVar4;
        String query = str;
        Intrinsics.checkNotNullParameter(query, "query");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(838823833);
        int i3 = i | (c0814p.f(query) ? 4 : 2) | (c0814p.f(searchType) ? 32 : 16) | 384 | (c0814p.c(f) ? 2048 : 1024) | (c0814p.h(rVar) ? 16384 : 8192) | (c0814p.h(cVar) ? 131072 : 65536) | (c0814p.h(function2) ? 1048576 : 524288) | (c0814p.h(function22) ? 8388608 : 4194304) | (c0814p.h(cVar2) ? 67108864 : 33554432) | (c0814p.h(cVar3) ? 536870912 : 268435456);
        int i4 = (c0814p.h(function23) ? 4 : 2) | (c0814p.h(function1) ? 32 : 16) | (c0814p.h(function12) ? 256 : 128);
        if ((i3 & 306783379) == 306783378 && (i4 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar4 = nVar;
        } else {
            c0814p.S();
            int i5 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i5 == 0 || c0814p.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p.Q();
                nVar2 = nVar;
            }
            c0814p.q();
            rVar.getClass();
            Intrinsics.checkNotNullParameter(query, "query");
            boolean zB = Intrinsics.b(rVar.f, query);
            com.quizlet.search.data.blended.g gVar = com.quizlet.search.data.blended.g.a;
            kotlinx.coroutines.flow.s0 s0Var = rVar.e;
            if (zB) {
                i2 = i4;
            } else {
                while (true) {
                    Object value = s0Var.getValue();
                    if (s0Var.k(value, gVar)) {
                        break;
                    } else {
                        query = str;
                    }
                }
                rVar.f = query;
                i2 = i4;
                kotlinx.coroutines.E.A(androidx.lifecycle.p0.j(rVar), rVar.i, null, new com.quizlet.search.viewmodels.q(rVar, query, null), 2);
            }
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(s0Var, c0814p);
            androidx.compose.foundation.lazy.grid.A a = androidx.compose.foundation.lazy.grid.B.a(0, c0814p, 3);
            com.quizlet.search.data.blended.i iVar = (com.quizlet.search.data.blended.i) interfaceC0773a0M.getValue();
            if (Intrinsics.b(iVar, gVar)) {
                c0814p.X(597495212);
                AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), c0814p, 0, 1);
                c0814p.p(false);
                c0814p = c0814p;
                nVar3 = nVar2;
            } else {
                if (!(iVar instanceof com.quizlet.search.data.blended.h)) {
                    throw com.google.android.gms.measurement.internal.Z.j(597493823, c0814p, false);
                }
                c0814p.X(1342617891);
                Object value2 = interfaceC0773a0M.getValue();
                Intrinsics.e(value2, "null cannot be cast to non-null type com.quizlet.search.data.blended.SearchAllResultsUiState.MainState");
                com.quizlet.search.data.blended.h hVar = (com.quizlet.search.data.blended.h) value2;
                c0814p.X(597511902);
                boolean zH = c0814p.h(rVar);
                Object objI = c0814p.I();
                if (zH || objI == v) {
                    com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y(1, rVar, com.quizlet.search.viewmodels.r.class, "onItemImpression", "onItemImpression(Lcom/quizlet/ui/models/impressions/ImpressionableItem;)V", 0, 23);
                    c0814p.i0(yVar);
                    objI = yVar;
                }
                c0814p.p(false);
                int i6 = i3 >> 9;
                nVar3 = nVar2;
                c(hVar, searchType, cVar, function2, function22, cVar2, cVar3, function23, function12, function1, (Function1) ((kotlin.reflect.f) objI), nVar3, f, a, c0814p, (i3 & ContentType.LONG_FORM_ON_DEMAND) | (i6 & 896) | (i6 & 7168) | (57344 & i6) | (458752 & i6) | (i6 & 3670016) | ((i2 << 21) & 29360128) | ((i2 << 18) & 234881024) | ((i2 << 24) & 1879048192), (i3 >> 3) & 1008);
                c0814p = c0814p;
                c0814p.p(false);
            }
            nVar4 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(str, searchType, nVar4, f, rVar, cVar, function2, function22, cVar2, cVar3, function23, function1, function12, i) { // from class: com.quizlet.search.composables.k
                public final /* synthetic */ String a;
                public final /* synthetic */ SearchType b;
                public final /* synthetic */ androidx.compose.ui.n c;
                public final /* synthetic */ float d;
                public final /* synthetic */ com.quizlet.search.viewmodels.r e;
                public final /* synthetic */ kotlin.jvm.functions.c f;
                public final /* synthetic */ Function2 g;
                public final /* synthetic */ Function2 h;
                public final /* synthetic */ kotlin.jvm.functions.c i;
                public final /* synthetic */ kotlin.jvm.functions.c j;
                public final /* synthetic */ Function2 k;
                public final /* synthetic */ Function1 l;
                public final /* synthetic */ Function1 m;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    Function1 function13 = this.l;
                    Function1 function14 = this.m;
                    AbstractC3209n0.d(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, function13, function14, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final long e(long j, boolean z, int i, float f) {
        int iMin = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        int iH = ((z || i == 2) && androidx.compose.ui.unit.a.d(j)) ? androidx.compose.ui.unit.a.h(j) : Integer.MAX_VALUE;
        if (androidx.compose.ui.unit.a.j(j) != iH) {
            iH = kotlin.ranges.l.c(AbstractC0484d0.q(f), androidx.compose.ui.unit.a.j(j), iH);
        }
        int iG = androidx.compose.ui.unit.a.g(j);
        int iMin2 = Math.min(0, 262142);
        int iMin3 = iH == Integer.MAX_VALUE ? Integer.MAX_VALUE : Math.min(iH, 262142);
        int iG2 = L5.g(iMin3 == Integer.MAX_VALUE ? iMin2 : iMin3);
        if (iG != Integer.MAX_VALUE) {
            iMin = Math.min(iG2, iG);
        }
        return L5.a(iMin2, iMin3, Math.min(iG2, 0), iMin);
    }
}
