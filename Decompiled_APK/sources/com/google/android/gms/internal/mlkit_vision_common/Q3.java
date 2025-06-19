package com.google.android.gms.internal.mlkit_vision_common;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.K5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Q3 {
    public static final void a(com.quizlet.data.model.m2 source, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Pair pair;
        String str;
        Intrinsics.checkNotNullParameter(source, "source");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1320809576);
        if ((((c0814p.f(source) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            C0386g c0386g = AbstractC0398m.e;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0382e.u(qVar, com.quizlet.ui.resources.designsystem.generated.j.i).g(androidx.compose.foundation.layout.K0.c), "generatingContent");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0386g, gVar, c0814p, 54);
            int i2 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            Intrinsics.checkNotNullParameter(source, "<this>");
            c0814p.X(-1840414114);
            int iOrdinal = source.ordinal();
            if (iOrdinal == 0) {
                c0814p.X(-1543137322);
                androidx.compose.runtime.B b = com.quizlet.themes.g.a;
                C0861v c0861v = new C0861v(((com.quizlet.themes.b) c0814p.j(b)).F());
                ((com.quizlet.themes.b) c0814p.j(b)).c.getClass();
                pair = new Pair(c0861v, new C0861v(com.quizlet.ui.resources.designsystem.generated.d.G));
                c0814p.p(false);
            } else if (iOrdinal == 1) {
                c0814p.X(-1543131946);
                androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
                C0861v c0861v2 = new C0861v(((com.quizlet.themes.b) c0814p.j(b2)).F());
                ((com.quizlet.themes.b) c0814p.j(b2)).c.getClass();
                pair = new Pair(c0861v2, new C0861v(com.quizlet.ui.resources.designsystem.generated.d.G));
                c0814p.p(false);
            } else {
                if (iOrdinal != 2) {
                    throw com.google.android.gms.measurement.internal.Z.j(-1543138956, c0814p, false);
                }
                c0814p.X(-1543126438);
                androidx.compose.runtime.B b3 = com.quizlet.themes.g.a;
                ((com.quizlet.themes.b) c0814p.j(b3)).c.getClass();
                pair = new Pair(new C0861v(com.quizlet.ui.resources.designsystem.generated.d.O), new C0861v(((com.quizlet.themes.b) c0814p.j(b3)).D()));
                c0814p.p(false);
            }
            c0814p.p(false);
            long j = ((C0861v) pair.a).a;
            long j2 = ((C0861v) pair.b).a;
            Intrinsics.checkNotNullParameter(source, "<this>");
            c0814p.X(-572278731);
            if (source == com.quizlet.data.model.m2.a) {
                throw new kotlin.n(null, 1, null);
            }
            if (source == com.quizlet.data.model.m2.b) {
                throw new kotlin.n(null, 1, null);
            }
            if (source != com.quizlet.data.model.m2.c) {
                throw new NoWhenBranchMatchedException();
            }
            String strD = AbstractC3106b5.d(c0814p, R.string.uuf_generating_practice_test_text);
            c0814p.p(false);
            com.quizlet.ui.compose.animations.a aVarC = K5.c(AbstractC3409x1.h(strD), j, j2, c0814p);
            Intrinsics.checkNotNullParameter(source, "<this>");
            c0814p.X(890017429);
            int iOrdinal2 = source.ordinal();
            if (iOrdinal2 == 0) {
                throw new kotlin.n(null, 1, null);
            }
            if (iOrdinal2 == 1) {
                throw new kotlin.n(null, 1, null);
            }
            if (iOrdinal2 != 2) {
                throw new NoWhenBranchMatchedException();
            }
            c0814p.p(false);
            com.airbnb.lottie.h hVar = (com.airbnb.lottie.h) r.d(new com.airbnb.lottie.compose.o(R.raw.lottie_generating_practice_tests), c0814p).getValue();
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.themes.m.C0);
            Intrinsics.checkNotNullParameter(source, "<this>");
            int iOrdinal3 = source.ordinal();
            if (iOrdinal3 == 0) {
                str = "generationImageStudyGuides";
            } else if (iOrdinal3 == 1) {
                str = "generationImageFlashcards";
            } else {
                if (iOrdinal3 != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                str = "generationImagePracticeTests";
            }
            AbstractC3515q.a(hVar, androidx.compose.ui.platform.N.G(qVarK, str), SubsamplingScaleImageView.TILE_SIZE_AUTO, null, null, c0814p, 1572864, 0, 4194236);
            androidx.compose.runtime.B b4 = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L lA = androidx.compose.ui.text.L.a(((com.quizlet.themes.f) c0814p.j(b4)).d, aVarC.b);
            mVar.p();
            androidx.compose.material3.Q4.b(aVarC.a, androidx.compose.foundation.layout.K0.d(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), com.quizlet.themes.m.I), 0L, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, lA, c0814p, 0, 0, 65020);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.uuf_generating_description);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b4)).j;
            long jF = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f();
            mVar.s();
            androidx.compose.material3.Q4.b(strD2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jF, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65016);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.common.c(source, qVar, i, 1);
        }
    }

    public static String b(String str, Object... objArr) {
        int length;
        int length2;
        int iIndexOf;
        String strE;
        int i = 0;
        int i2 = 0;
        while (true) {
            length = objArr.length;
            if (i2 >= length) {
                break;
            }
            Object obj = objArr[i2];
            if (obj == null) {
                strE = "null";
            } else {
                try {
                    strE = obj.toString();
                } catch (Exception e) {
                    String strL = android.support.v4.media.session.a.l(obj.getClass().getName(), "@", Integer.toHexString(System.identityHashCode(obj)));
                    Logger.getLogger("com.google.common.base.Strings").logp(Level.WARNING, "com.google.common.base.Strings", "lenientToString", "Exception during lenientFormat for ".concat(strL), (Throwable) e);
                    strE = AbstractC0147y.e(SimpleComparison.LESS_THAN_OPERATION, strL, " threw ", e.getClass().getName(), SimpleComparison.GREATER_THAN_OPERATION);
                }
            }
            objArr[i2] = strE;
            i2++;
        }
        StringBuilder sb = new StringBuilder(str.length() + (length * 16));
        int i3 = 0;
        while (true) {
            length2 = objArr.length;
            if (i >= length2 || (iIndexOf = str.indexOf("%s", i3)) == -1) {
                break;
            }
            sb.append((CharSequence) str, i3, iIndexOf);
            sb.append(objArr[i]);
            i++;
            i3 = iIndexOf + 2;
        }
        sb.append((CharSequence) str, i3, str.length());
        if (i < length2) {
            sb.append(" [");
            sb.append(objArr[i]);
            for (int i4 = i + 1; i4 < objArr.length; i4++) {
                sb.append(", ");
                sb.append(objArr[i4]);
            }
            sb.append(']');
        }
        return sb.toString();
    }
}
