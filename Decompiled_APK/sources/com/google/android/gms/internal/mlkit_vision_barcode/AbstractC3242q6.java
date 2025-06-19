package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.content.Intent;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
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
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.assembly.compose.buttons.C4078c;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.quizletandroid.R;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;
import java.util.Locale;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.q6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3242q6 {
    public static final void a(com.quizlet.assembly.compose.modals.x modalState, kotlinx.collections.immutable.b studyOptions, Function1 onStudyModeClick, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        Intrinsics.checkNotNullParameter(studyOptions, "studyOptions");
        Intrinsics.checkNotNullParameter(onStudyModeClick, "onStudyModeClick");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(144910588);
        if (((i | (c0814p2.h(modalState) ? 4 : 2) | (c0814p2.f(studyOptions) ? 32 : 16) | (c0814p2.h(onStudyModeClick) ? 256 : 128) | 3072) & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p2.X(2039104571);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.y(onStudyModeClick, modalState, 3);
                c0814p2.i0(objI);
            }
            Function1 function1 = (Function1) objI;
            c0814p2.p(false);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.h();
            float f = com.quizlet.ui.resources.designsystem.generated.h.g;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarV = AbstractC0382e.v(nVar, f, f2);
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            C0380d c0380d = AbstractC0398m.a;
            mVar.s();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(f2), gVar, c0814p2, 48);
            int i2 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVarV);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, bA, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p2, i2, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            mVar.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f2, 7);
            String strD = AbstractC3106b5.d(c0814p2, R.string.study_folder_modal_header);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).e;
            qVar2 = nVar;
            androidx.compose.material3.Q4.b(strD, qVarY, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p2, 0, 0, 65532);
            c0814p = c0814p2;
            c0814p.X(-728088587);
            Iterator<E> it2 = studyOptions.iterator();
            while (it2.hasNext()) {
                com.quizlet.features.infra.folder.study.data.a aVar = (com.quizlet.features.infra.folder.study.data.a) it2.next();
                androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(qVar2, 1.0f);
                aVar.getClass();
                c0814p.X(1013693006);
                String strD2 = AbstractC3106b5.d(c0814p, R.string.learn);
                c0814p.p(false);
                c0814p.X(-1464352659);
                androidx.compose.ui.graphics.painter.b bVarF = ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).b.f(c0814p);
                c0814p.p(false);
                C4097w c4097w = C4097w.a;
                androidx.compose.runtime.B b = com.quizlet.themes.g.a;
                long j = ((com.quizlet.themes.b) c0814p.j(b)).f;
                long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
                long jB = ((com.quizlet.themes.b) c0814p.j(b)).b.b();
                long jO = ((com.quizlet.themes.b) c0814p.j(b)).o();
                ((com.quizlet.themes.b) c0814p.j(b)).c.getClass();
                C4078c c4078c = new C4078c(j, jE, jB, jO, com.quizlet.ui.resources.designsystem.generated.d.r, 32);
                C4076a c4076a = C4076a.d;
                c0814p.X(11155950);
                boolean zH = c0814p.h(aVar);
                Object objI2 = c0814p.I();
                if (zH || objI2 == v) {
                    objI2 = new com.quizlet.data.repository.explanations.exercise.a(19, function1, aVar);
                    c0814p.i0(objI2);
                }
                c0814p.p(false);
                C0814p c0814p3 = c0814p;
                com.google.android.gms.internal.mlkit_vision_document_scanner.T4.b(strD2, c4078c, qVarC2, (Function0) objI2, false, c4097w, c4076a, null, null, bVarF, null, false, c0814p3, 384, 48, 1424);
                c0814p = c0814p3;
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(modalState, studyOptions, onStudyModeClick, qVar2, i, 14);
        }
    }

    public static final void b(com.quizlet.assembly.compose.modals.x modalState, kotlinx.collections.immutable.b studyOptions, Function1 onStudyModeClick, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        Intrinsics.checkNotNullParameter(studyOptions, "studyOptions");
        Intrinsics.checkNotNullParameter(onStudyModeClick, "onStudyModeClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-259661328);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(modalState) : c0814p.h(modalState) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(studyOptions) : c0814p.h(studyOptions) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(onStudyModeClick) ? 256 : 128;
        }
        int i3 = i2 | 3072;
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.b(modalState, androidx.compose.ui.platform.N.G(nVar, "StudyFolderModal"), false, null, null, null, androidx.compose.runtime.internal.e.e(1573207253, new com.quizlet.assembly.compose.menu.l(modalState, studyOptions, onStudyModeClick, 12), c0814p), c0814p, 1572872 | (i3 & 14), 60);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i((Object) modalState, (Object) studyOptions, (Object) onStudyModeClick, qVar2, i, 13);
        }
    }

    public static void c(String str, boolean z) {
        if (!z) {
            throw new IllegalArgumentException(String.valueOf(str));
        }
    }

    public static void d(boolean z) {
        if (!z) {
            throw new IllegalArgumentException();
        }
    }

    public static void e(int i, int i2, String str, int i3) {
        if (i < i2) {
            Locale locale = Locale.US;
            throw new IllegalArgumentException(str + " is out of range of [" + i2 + ", " + i3 + "] (too low)");
        }
        if (i <= i3) {
            return;
        }
        Locale locale2 = Locale.US;
        throw new IllegalArgumentException(str + " is out of range of [" + i2 + ", " + i3 + "] (too high)");
    }

    public static void f(int i) {
        if (i < 0) {
            throw new IllegalArgumentException();
        }
    }

    public static void g(Object obj, String str) {
        if (obj == null) {
            throw new NullPointerException(String.valueOf(str));
        }
    }

    public static void h(String str, boolean z) {
        if (!z) {
            throw new IllegalStateException(str);
        }
    }

    public static Intent i(Context context, String source, com.quizlet.features.infra.models.upgrade.a navigationSource) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
        Intent intent = new Intent(context, (Class<?>) UpgradeActivity.class);
        intent.putExtra("UpgradeSource", source);
        intent.putExtra("NavigationSource", navigationSource);
        return intent;
    }
}
