package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_document_scanner.R4;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class j3 {
    public static final void a(DiagramData diagram, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(diagram, "diagram");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-681691187);
        if ((((c0814p.h(diagram) ? 4 : 2) | i | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            qVar2 = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar2);
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
            androidx.compose.ui.q qVarA = androidx.compose.foundation.layout.C.a(androidx.compose.ui.platform.N.G(qVar2, "diagramCard"), 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.p();
            float f = com.quizlet.ui.resources.designsystem.generated.j.j;
            mVar.v();
            androidx.compose.ui.q qVarV = AbstractC0382e.v(qVarA, f, com.quizlet.ui.resources.designsystem.generated.j.l);
            mVar.e();
            R4.a(qVarV, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.f), 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(246827421, new com.quizlet.assembly.compose.cards.c(diagram, 15), c0814p), c0814p, 0, 1020);
            c0814p = c0814p;
            k3.a(null, null, null, null, c0814p, 0, 15);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(diagram, qVar2, i, 2);
        }
    }

    public static final List b(assistantMode.enums.C c) {
        Intrinsics.checkNotNullParameter(c, "<this>");
        int iOrdinal = c.ordinal();
        if (iOrdinal != 0 && iOrdinal != 1) {
            if (iOrdinal == 2) {
                return kotlin.collections.B.j(assistantMode.enums.k.d, assistantMode.enums.k.f);
            }
            if (iOrdinal != 3 && iOrdinal != 4 && iOrdinal != 5) {
                throw new NoWhenBranchMatchedException();
            }
        }
        return kotlin.collections.B.j(assistantMode.enums.k.d, assistantMode.enums.k.b);
    }

    public static final int c(String s, String t) {
        int i;
        Intrinsics.checkNotNullParameter(s, "s");
        Intrinsics.checkNotNullParameter(t, "t");
        if (Intrinsics.b(s, t)) {
            return 0;
        }
        if (Intrinsics.b(s, "")) {
            return t.length();
        }
        if (Intrinsics.b(t, "")) {
            return s.length();
        }
        int length = t.length() + 1;
        int[] iArr = new int[length];
        for (int i2 = 0; i2 < length; i2++) {
            iArr[i2] = i2;
        }
        int[] iArr2 = new int[t.length() + 1];
        int length2 = s.length();
        int i3 = 0;
        while (i3 < length2) {
            int i4 = i3 + 1;
            iArr2[0] = i4;
            int length3 = t.length();
            int i5 = 0;
            while (i5 < length3) {
                int i6 = i5 + 1;
                iArr2[i6] = Math.min(iArr2[i5] + 1, Math.min(iArr[i6] + 1, iArr[i5] + (s.charAt(i3) == t.charAt(i5) ? 0 : 1)));
                i5 = i6;
            }
            int length4 = t.length();
            if (length4 >= 0) {
                while (true) {
                    iArr[i] = iArr2[i];
                    i = i != length4 ? i + 1 : 0;
                }
            }
            i3 = i4;
        }
        return iArr2[t.length()];
    }
}
