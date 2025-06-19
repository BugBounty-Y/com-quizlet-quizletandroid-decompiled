package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.AdvertisementType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3578a5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y4;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.quizletandroid.R;
import java.io.EOFException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.p2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3379p2 {
    public static final void a(Function0 buttonState, Function0 hasAnsweredQuestion, Function0 isPreviousEnabled, Function0 onPreviousClick, Function0 onAllQuestionsClick, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(buttonState, "buttonState");
        Intrinsics.checkNotNullParameter(hasAnsweredQuestion, "hasAnsweredQuestion");
        Intrinsics.checkNotNullParameter(isPreviousEnabled, "isPreviousEnabled");
        Intrinsics.checkNotNullParameter(onPreviousClick, "onPreviousClick");
        Intrinsics.checkNotNullParameter(onAllQuestionsClick, "onAllQuestionsClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(485224538);
        int i2 = i | (c0814p.h(buttonState) ? 4 : 2) | (c0814p.h(hasAnsweredQuestion) ? 32 : 16) | (c0814p.h(isPreviousEnabled) ? 256 : 128) | (c0814p.h(onPreviousClick) ? 2048 : 1024) | (c0814p.h(onAllQuestionsClick) ? 16384 : 8192) | (c0814p.f(qVar) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(AbstractC0460p.f(qVar, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), androidx.compose.ui.graphics.F.a), 1.0f), "practice_test_taking_bottom_bar");
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.s();
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h), androidx.compose.ui.b.j, c0814p, 0);
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
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarM = com.quizlet.ui.resources.icons.d.m(c0814p);
            String strD = AbstractC3106b5.d(c0814p, R.string.practice_test_taking_previous_question_content_description);
            boolean zBooleanValue = ((Boolean) isPreviousEnabled.invoke()).booleanValue();
            C4076a c4076a = C4076a.e;
            AbstractC3578a5.a(bVarM, strD, null, onPreviousClick, zBooleanValue, c4076a, null, 0L, c0814p, i2 & 7168, 196);
            b((com.quizlet.features.practicetest.takingtest.e) buttonState.invoke(), hasAnsweredQuestion, c0814p, ((i2 << 3) & 896) | 6);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            c0814p.X(-157861682);
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_sys_list, c0814p, 0);
            c0814p.p(false);
            AbstractC3578a5.a(bVarA, AbstractC3106b5.d(c0814p, R.string.practice_test_taking_all_questions_content_description), null, onAllQuestionsClick, false, c4076a, null, 0L, c0814p, (i2 >> 3) & 7168, AdvertisementType.ON_DEMAND_MID_ROLL);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e(buttonState, hasAnsweredQuestion, isPreviousEnabled, onPreviousClick, onAllQuestionsClick, qVar, i);
        }
    }

    public static final void b(com.quizlet.features.practicetest.takingtest.e eVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.foundation.layout.I0 i0 = androidx.compose.foundation.layout.I0.a;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1812564777);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(i0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(eVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            boolean zBooleanValue = ((Boolean) function0.invoke()).booleanValue();
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (zBooleanValue) {
                c0814p.X(-1381883227);
                W4.a(AbstractC3106b5.d(c0814p, eVar.a), androidx.compose.ui.platform.N.G(i0.a(nVar, 1.0f, true), "primary_button"), eVar.a(), false, null, null, null, null, null, false, c0814p, 0, 1016);
                c0814p.p(false);
            } else {
                c0814p.X(-1381623199);
                Y4.b(AbstractC3106b5.d(c0814p, eVar.a), androidx.compose.ui.platform.N.G(i0.a(nVar, 1.0f, true), "secondary_button"), eVar.a(), false, null, null, 0L, 0L, null, null, null, c0814p, 0, 0, 4088);
                c0814p = c0814p;
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(eVar, function0, i, 15);
        }
    }

    public static boolean c(String str) {
        androidx.webkit.internal.b bVar = androidx.webkit.internal.s.a;
        Set<androidx.webkit.internal.j> setUnmodifiableSet = Collections.unmodifiableSet(androidx.webkit.internal.c.c);
        HashSet hashSet = new HashSet();
        for (androidx.webkit.internal.j jVar : setUnmodifiableSet) {
            if (((androidx.webkit.internal.c) jVar).a.equals(str)) {
                hashSet.add(jVar);
            }
        }
        if (hashSet.isEmpty()) {
            throw new RuntimeException("Unknown feature ".concat(str));
        }
        Iterator it2 = hashSet.iterator();
        while (it2.hasNext()) {
            androidx.webkit.internal.c cVar = (androidx.webkit.internal.c) ((androidx.webkit.internal.j) it2.next());
            if (cVar.a() || cVar.b()) {
                return true;
            }
        }
        return false;
    }

    public static final boolean d(C5091h c5091h) {
        C5091h c5091h2;
        int i;
        Intrinsics.checkNotNullParameter(c5091h, "<this>");
        try {
            c5091h2 = new C5091h();
            long j = c5091h.b;
            long j2 = 64;
            if (j <= 64) {
                j2 = j;
            }
            c5091h.l(c5091h2, 0L, j2);
        } catch (EOFException unused) {
        }
        for (i = 0; i < 16; i++) {
            if (c5091h2.u()) {
                return true;
            }
            int iD0 = c5091h2.d0();
            if (Character.isISOControl(iD0) && !Character.isWhitespace(iD0)) {
                return false;
            }
        }
        return true;
    }
}
