package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.vector.C0867f;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3293x0;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.assembly.compose.buttons.C4078c;
import com.quizlet.assembly.compose.buttons.C4093s;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.quizletandroid.R;
import com.quizlet.search.composables.AbstractC4788g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.x0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3293x0 {
    public static C0867f a;

    public static final void a(int i, com.quizlet.assembly.compose.modals.x xVar, InterfaceC0806l interfaceC0806l, int i2) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-928882146);
        int i3 = (c0814p2.d(i) ? 4 : 2) | i2 | (c0814p2.h(xVar) ? 32 : 16);
        if ((i3 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i2 & 1) != 0 && !c0814p2.w()) {
                c0814p2.Q();
            }
            c0814p2.q();
            String strD = AbstractC3106b5.d(c0814p2, R.string.search_set_filter_header_label);
            c0814p2.X(1145809306);
            boolean z = (((i3 & ContentType.LONG_FORM_ON_DEMAND) ^ 48) > 32 && c0814p2.h(xVar)) || (i3 & 48) == 32;
            Object objI = c0814p2.I();
            if (z || objI == C0804k.a) {
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.a aVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.a(0, xVar, com.quizlet.assembly.compose.modals.x.class, "show", "show(Landroid/os/Bundle;)V", 0, 2);
                c0814p2.i0(aVar);
                objI = aVar;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.Y4.b(strD, androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f), (Function0) objI, false, null, null, 0L, 0L, C4093s.a, AbstractC4788g.a, androidx.compose.runtime.internal.e.e(1761727491, new com.quizlet.search.composables.H(i), c0814p2), c0814p, 48, 54, 504);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.t(i, xVar, i2);
        }
    }

    public static final void b(final String query, final com.quizlet.assembly.compose.modals.x filtersModalState, final SearchType searchType, androidx.compose.ui.n nVar, final float f, final com.quizlet.search.viewmodels.A a2, final kotlin.jvm.functions.c cVar, final kotlin.jvm.functions.c cVar2, InterfaceC0806l interfaceC0806l, final int i) {
        androidx.compose.ui.n nVar2;
        boolean z;
        Object obj;
        androidx.compose.foundation.lazy.grid.A a3;
        androidx.compose.ui.n nVar3;
        int i2;
        C0814p c0814p;
        final androidx.compose.ui.n nVar4;
        Intrinsics.checkNotNullParameter(query, "query");
        Intrinsics.checkNotNullParameter(filtersModalState, "filtersModalState");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-2117730436);
        int i3 = i | (c0814p2.f(query) ? 4 : 2) | (c0814p2.h(filtersModalState) ? 32 : 16) | (c0814p2.f(searchType) ? 256 : 128) | 3072 | (c0814p2.c(f) ? 16384 : 8192) | (c0814p2.h(a2) ? 131072 : 65536) | (c0814p2.h(cVar) ? 1048576 : 524288) | (c0814p2.h(cVar2) ? 8388608 : 4194304);
        if ((4793491 & i3) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            nVar4 = nVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 == 0 || c0814p2.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p2.Q();
                nVar2 = nVar;
            }
            c0814p2.q();
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(a2.n, c0814p2);
            androidx.compose.foundation.lazy.grid.A a4 = androidx.compose.foundation.lazy.grid.B.a(0, c0814p2, 3);
            int iD = AbstractC3236q0.d(c0814p2);
            androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.K0.c(nVar2, 1.0f).g(androidx.compose.foundation.layout.K0.b);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            androidx.compose.ui.n nVar5 = nVar2;
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.foundation.layout.A0 a0C = Q5.c(new androidx.compose.foundation.layout.A0(f2, f2, f2, f2), f);
            C0380d c0380d = AbstractC0398m.a;
            mVar.s();
            C0392j c0392jG = AbstractC0398m.g(f2);
            mVar.s();
            C0392j c0392jG2 = AbstractC0398m.g(f2);
            c0814p2.X(430375934);
            boolean zH = c0814p2.h(a2) | ((i3 & 14) == 4);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                z = false;
                com.quizlet.search.composables.F f3 = new com.quizlet.search.composables.F(a2, query, false ? 1 : 0);
                c0814p2.i0(f3);
                obj = f3;
            } else {
                z = false;
                obj = objI;
            }
            Function0 function0 = (Function0) obj;
            c0814p2.p(z);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(1814818433, new com.quizlet.assembly.compose.tags.c(filtersModalState, f, interfaceC0773a0M), c0814p2);
            c0814p2.X(430410780);
            boolean zD = ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32 || c0814p2.h(filtersModalState)) | c0814p2.d(iD) | c0814p2.f(interfaceC0773a0M) | ((i3 & 896) == 256) | c0814p2.f(a4) | ((3670016 & i3) == 1048576) | ((29360128 & i3) == 8388608) | c0814p2.h(a2);
            Object objI2 = c0814p2.I();
            if (zD || objI2 == v) {
                a3 = a4;
                nVar3 = nVar5;
                com.quizlet.features.settings.composables.dialogs.e eVar = new com.quizlet.features.settings.composables.dialogs.e(iD, filtersModalState, interfaceC0773a0M, searchType, a3, cVar, cVar2, a2);
                i2 = iD;
                c0814p2.i0(eVar);
                objI2 = eVar;
            } else {
                i2 = iD;
                a3 = a4;
                nVar3 = nVar5;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3266t5.b(function0, qVarG, 0L, i2, a0C, c0392jG, c0392jG2, a3, dVarE, null, (Function2) objI2, c0814p, 100663296, 516);
            nVar4 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(query, filtersModalState, searchType, nVar4, f, a2, cVar, cVar2, i) { // from class: com.quizlet.search.composables.G
                public final /* synthetic */ String a;
                public final /* synthetic */ com.quizlet.assembly.compose.modals.x b;
                public final /* synthetic */ SearchType c;
                public final /* synthetic */ androidx.compose.ui.n d;
                public final /* synthetic */ float e;
                public final /* synthetic */ com.quizlet.search.viewmodels.A f;
                public final /* synthetic */ kotlin.jvm.functions.c g;
                public final /* synthetic */ kotlin.jvm.functions.c h;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj2, Object obj3) {
                    ((Integer) obj3).getClass();
                    int iH = C0776c.H(65);
                    kotlin.jvm.functions.c cVar3 = this.g;
                    kotlin.jvm.functions.c cVar4 = this.h;
                    AbstractC3293x0.b(this.a, this.b, this.c, this.d, this.e, this.f, cVar3, cVar4, (InterfaceC0806l) obj2, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void c(boolean z, androidx.compose.ui.n nVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        long jA;
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(466562208);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i & 384) == 0) {
            i3 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            com.quizlet.themes.e.a(c0814p).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarN = com.quizlet.ui.resources.icons.d.n(c0814p);
            String strD = AbstractC3106b5.d(c0814p, R.string.flashcards_content_description_speak);
            C4076a c4076a = C4076a.e;
            if (z) {
                c0814p.X(-721306963);
                jA = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).w;
                c0814p.p(false);
            } else {
                c0814p.X(-721214428);
                jA = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).A();
                c0814p.p(false);
            }
            long j = jA;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            com.google.android.gms.internal.mlkit_vision_document_scanner.V4.a(bVarN, strD, new C4078c(j, ((com.quizlet.themes.b) c0814p.j(b)).s(), ((com.quizlet.themes.b) c0814p.j(b)).A(), ((com.quizlet.themes.b) c0814p.j(b)).b.b(), ((com.quizlet.themes.b) c0814p.j(b)).t, 32), nVar3, function0, false, c4076a, null, null, c0814p, (i3 << 6) & 64512, 928);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.views.composables.p(z, nVar2, function0, i, 0);
        }
    }
}
