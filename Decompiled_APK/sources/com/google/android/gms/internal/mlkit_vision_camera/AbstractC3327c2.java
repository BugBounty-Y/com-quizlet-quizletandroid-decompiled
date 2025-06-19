package com.google.android.gms.internal.mlkit_vision_camera;

import android.text.format.DateUtils;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.navigation.compose.C1280m;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.R4;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.c2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3327c2 {
    public static final void a(Function1 function1, com.quizlet.data.model.V0 v0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1040114164);
        int i2 = (c0814p.h(function1) ? 4 : 2) | i | (c0814p.h(v0) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p.X(-1536744774);
            boolean zH = ((i2 & 14) == 4) | c0814p.h(v0);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.data.repository.explanations.exercise.a(28, function1, v0);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarL = AbstractC0460p.l(nVar, false, null, (Function0) objI, 7);
            com.quizlet.themes.m.g.n();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarL, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.o, 1);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
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
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.foundation.layout.I0 i0 = androidx.compose.foundation.layout.I0.a;
            c(0, 0, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).T0, c0814p, i0.a(nVar, 1.6f, true), v0.b);
            c(0, 4, 0L, c0814p, i0.a(nVar, 1.0f, true), AbstractC3106b5.c(R.string.practice_test_past_exam_score_percentage, new Object[]{Integer.valueOf(v0.d)}, c0814p));
            c(0, 4, 0L, c0814p, i0.a(nVar, 1.0f, true), AbstractC3106b5.c(R.string.practice_test_past_exam_results_display, new Object[]{Integer.valueOf(v0.e), Integer.valueOf(v0.f)}, c0814p));
            String elapsedTime = DateUtils.formatElapsedTime(v0.c);
            Intrinsics.checkNotNullExpressionValue(elapsedTime, "formatElapsedTime(...)");
            c(0, 4, 0L, c0814p, i0.a(nVar, 0.8f, true), elapsedTime);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(function1, v0, i, 27);
        }
    }

    public static final void b(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2011208563);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.n();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.o, 1);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i2 = c0814p.P;
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
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.foundation.layout.I0 i0 = androidx.compose.foundation.layout.I0.a;
            String strD = AbstractC3106b5.d(c0814p, R.string.practice_test_past_exam_date);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            c(0, 0, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), c0814p, i0.a(nVar, 1.6f, true), strD);
            c(0, 0, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), c0814p, i0.a(nVar, 1.0f, true), AbstractC3106b5.d(c0814p, R.string.practice_test_past_exam_score));
            c(0, 0, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), c0814p, i0.a(nVar, 1.0f, true), AbstractC3106b5.d(c0814p, R.string.practice_test_past_exam_results));
            c(0, 0, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), c0814p, i0.a(nVar, 0.8f, true), AbstractC3106b5.d(c0814p, R.string.practice_test_past_exam_time));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.x(i, 15);
        }
    }

    public static final void c(int i, int i2, long j, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str) {
        long j2;
        int i3;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(416489530);
        int i4 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16);
        int i5 = i2 & 4;
        if (i5 != 0) {
            i3 = i4 | 384;
            j2 = j;
        } else {
            j2 = j;
            i3 = i4 | (c0814p2.e(j2) ? 256 : 128);
        }
        if ((i3 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            if (i5 != 0) {
                j2 = C0861v.g;
            }
            long j3 = j2;
            c0814p = c0814p2;
            Q4.b(str, qVar, j3, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).j, c0814p, i3 & 1022, 0, 65528);
            j2 = j3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.x(str, qVar, j2, i, i2);
        }
    }

    public static final void d(kotlinx.collections.immutable.b pastExams, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(pastExams, "pastExams");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-2507686);
        int i2 = i | (c0814p2.h(pastExams) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            R4.a(qVar, null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(-1570620832, new androidx.navigation.compose.o(29, pastExams, function1), c0814p2), c0814p, (i2 >> 3) & 14, 1022);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.detail.composables.e(pastExams, qVar, function1, i, 0);
        }
    }

    public static boolean e(String current, String str) {
        Intrinsics.checkNotNullParameter(current, "current");
        if (Intrinsics.b(current, str)) {
            return true;
        }
        if (current.length() != 0) {
            int i = 0;
            int i2 = 0;
            int i3 = 0;
            while (true) {
                if (i < current.length()) {
                    char cCharAt = current.charAt(i);
                    int i4 = i3 + 1;
                    if (i3 == 0 && cCharAt != '(') {
                        break;
                    }
                    if (cCharAt != '(') {
                        if (cCharAt == ')' && i2 - 1 == 0 && i3 != current.length() - 1) {
                            break;
                        }
                    } else {
                        i2++;
                    }
                    i++;
                    i3 = i4;
                } else if (i2 == 0) {
                    String strSubstring = current.substring(1, current.length() - 1);
                    Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
                    return Intrinsics.b(StringsKt.g0(strSubstring).toString(), str);
                }
            }
        }
        return false;
    }
}
