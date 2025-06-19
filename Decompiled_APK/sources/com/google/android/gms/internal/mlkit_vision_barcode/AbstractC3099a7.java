package com.google.android.gms.internal.mlkit_vision_barcode;

import android.text.InputFilter;
import android.text.method.TransformationMethod;
import androidx.compose.foundation.AbstractC0460p;
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
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.CharsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.a7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3099a7 {
    public static final void a(String title, androidx.compose.ui.graphics.painter.b icon, androidx.compose.ui.q qVar, boolean z, InterfaceC0806l interfaceC0806l, int i, int i2) {
        androidx.compose.ui.q qVar2;
        int i3;
        boolean z2;
        androidx.compose.ui.q qVar3;
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(icon, "icon");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(869540891);
        int i4 = i | (c0814p.f(title) ? 4 : 2) | (c0814p.d(R.string.magic_notes_sample_essay) ? 32 : 16) | (c0814p.h(icon) ? 256 : 128);
        int i5 = i2 & 8;
        if (i5 != 0) {
            i3 = i4 | 3072;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i4 | (c0814p.f(qVar2) ? 2048 : 1024);
        }
        int i6 = i3 | 24576;
        if ((i6 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar2;
            z2 = z;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVar4 = i5 != 0 ? nVar : qVar2;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar4, 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i7 = c0814p.P;
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
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC2, c0912h4);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 6);
            int i8 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, nVar);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            androidx.compose.ui.q qVar5 = qVar4;
            String strD = AbstractC3106b5.d(c0814p, R.string.magic_notes_sample_essay);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.u();
            float f = com.quizlet.ui.resources.designsystem.generated.j.g;
            AbstractC0460p.c(icon, strD, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, 11), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, (i6 >> 6) & 14, 120);
            c0814p.X(2026271025);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.magic_notes_sample_essay);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jF = ((com.quizlet.themes.b) c0814p.j(b)).b.f();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.b;
            androidx.compose.material3.Q4.b(strD2, null, jF, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).j, c0814p, 0, 0, 65530);
            c0814p.p(false);
            c0814p.p(true);
            long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b2)).i;
            mVar.u();
            androidx.compose.material3.Q4.b(title, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, i6 & 14, 0, 65528);
            c0814p = c0814p;
            c0814p.p(true);
            z2 = true;
            qVar3 = qVar5;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.recyclerview.step.g(title, icon, qVar3, z2, i, i2);
        }
    }

    public static final void b(io.ktor.http.u uVar, String str, int i, int i2, int i3) {
        if (i2 == -1) {
            int iH = h(i, i3, str);
            int iG = g(iH, i3, str);
            if (iG > iH) {
                String strSubstring = str.substring(iH, iG);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                uVar.e(strSubstring, kotlin.collections.K.a);
                return;
            }
            return;
        }
        int iH2 = h(i, i2, str);
        int iG2 = g(iH2, i2, str);
        if (iG2 > iH2) {
            String strSubstring2 = str.substring(iH2, iG2);
            Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
            int iH3 = h(i2 + 1, i3, str);
            String strSubstring3 = str.substring(iH3, g(iH3, i3, str));
            Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
            uVar.m(strSubstring2, strSubstring3);
        }
    }

    public static final int g(int i, int i2, String str) {
        while (i2 > i && CharsKt.b(str.charAt(i2 - 1))) {
            i2--;
        }
        return i2;
    }

    public static final int h(int i, int i2, String str) {
        while (i < i2 && CharsKt.b(str.charAt(i))) {
            i++;
        }
        return i;
    }

    public abstract InputFilter[] c(InputFilter[] inputFilterArr);

    public abstract boolean d();

    public abstract void e(boolean z);

    public abstract void f(boolean z);

    public abstract TransformationMethod i(TransformationMethod transformationMethod);
}
