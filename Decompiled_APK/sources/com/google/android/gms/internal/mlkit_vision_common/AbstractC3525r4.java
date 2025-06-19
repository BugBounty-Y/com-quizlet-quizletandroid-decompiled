package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.ZIndexElement;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.ads.C2673tu;
import com.google.android.gms.internal.ads.C2716uu;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3169i5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.common.base.Function;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.RandomAccess;
import java.util.Set;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.r4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3525r4 {
    public static final void a(com.quizlet.learn.ui.progress.g gVar, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(506063242);
        if ((i & 6) == 0) {
            i2 = i | (c0814p.f(gVar) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.m, c0814p, 6);
            int i3 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC2, c0912h4);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            com.quizlet.learn.ui.progress.f fVar = com.quizlet.learn.ui.progress.f.b;
            c0814p.X(714160503);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new com.quizlet.features.settings.composables.changeusername.c(14);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            B4.b(gVar, fVar, (Function0) objI, qVarC3, c0814p, (i2 & 14) | 3504);
            com.quizlet.themes.m.g.s();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, com.quizlet.ui.resources.designsystem.generated.j.h));
            androidx.compose.ui.q qVarC4 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g, androidx.compose.ui.b.j, c0814p, 6);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC5 = androidx.compose.ui.a.c(c0814p, qVarC4);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC5, c0912h4);
            String strD = AbstractC3106b5.d(c0814p, R.string.learn_summary_progress_correct_label);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b(strD, null, jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).k, c0814p, 0, 0, 65530);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.learn_summary_progress_total_label), null, ((com.quizlet.themes.b) c0814p.j(b)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).k, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.learn.checkpoint.ui.a(gVar, qVar, i, 1, (byte) 0);
        }
    }

    public static final void b(com.quizlet.learn.ui.progress.g gVar, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0913i c0913i;
        C0912h c0912h;
        com.quizlet.learn.ui.progress.g gVar2 = gVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1750369860);
        if ((i & 6) == 0) {
            i2 = i | (c0814p.f(gVar2) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.u();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarC, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.m, c0814p, 6);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarY);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i2 = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i2);
            } else {
                c0814p.l0();
            }
            C0912h c0912h2 = C0914j.f;
            C0776c.E(c0814p, bA, c0912h2);
            C0912h c0912h3 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h3);
            C0912h c0912h4 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h4);
            }
            C0912h c0912h5 = C0914j.d;
            C0776c.E(c0814p, qVarC2, c0912h5);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.K0.c(nVar, 1.0f).g(new ZIndexElement());
            com.quizlet.learn.ui.progress.f fVar = com.quizlet.learn.ui.progress.f.b;
            c0814p.X(-806505861);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new com.quizlet.features.settings.composables.changeusername.c(15);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            com.quizlet.learn.ui.progress.e.b(gVar2.a, gVar2.b, gVar2.c, fVar, qVarG, 0L, 0L, 0L, null, (Function0) objI, c0814p, 805334016);
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, f));
            androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g, androidx.compose.ui.b.j, c0814p, 6);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC4 = androidx.compose.ui.a.c(c0814p, qVarC3);
            c0814p.b0();
            if (c0814p.O) {
                c0913i = c0913i2;
                c0814p.k(c0913i);
            } else {
                c0913i = c0913i2;
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h2);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h3);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                c0912h = c0912h4;
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            } else {
                c0912h = c0912h4;
            }
            C0776c.E(c0814p, qVarC4, c0912h5);
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            C0380d c0380d = AbstractC0398m.a;
            androidx.compose.foundation.layout.G0 g0B2 = androidx.compose.foundation.layout.E0.b(c0380d, hVar, c0814p, 48);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
            androidx.compose.ui.q qVarC5 = androidx.compose.ui.a.c(c0814p, nVar);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B2, c0912h2);
            C0776c.E(c0814p, interfaceC0803j0L3, c0912h3);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC5, c0912h5);
            String strValueOf = String.valueOf(gVar2.a);
            com.quizlet.learn.ui.progress.i iVar = gVar2.d;
            C0912h c0912h6 = c0912h;
            C0913i c0913i3 = c0913i;
            B4.a(strValueOf, ((C0861v) iVar.a.invoke(c0814p, 0)).a, ((C0861v) iVar.b.invoke(c0814p, 0)).a, "left_pill_label", null, AbstractC3169i5.g(c0814p).g, null, gVar2.f, c0814p, 3072, 80);
            mVar.s();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.o(nVar, f));
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.learn_summary_progress_correct_label), null, AbstractC3169i5.f(c0814p).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, AbstractC3169i5.g(c0814p).g, c0814p, 0, 0, 65530);
            c0814p.p(true);
            androidx.compose.foundation.layout.G0 g0B3 = androidx.compose.foundation.layout.E0.b(c0380d, hVar, c0814p, 48);
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L4 = c0814p.l();
            androidx.compose.ui.q qVarC6 = androidx.compose.ui.a.c(c0814p, nVar);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i3);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B3, c0912h2);
            C0776c.E(c0814p, interfaceC0803j0L4, c0912h3);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h6);
            }
            C0776c.E(c0814p, qVarC6, c0912h5);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.learn_summary_progress_total_label), null, AbstractC3169i5.f(c0814p).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, AbstractC3169i5.g(c0814p).g, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            mVar.s();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.o(nVar, f));
            gVar2 = gVar;
            B4.a(String.valueOf(gVar2.c), AbstractC3169i5.f(c0814p).b.b(), AbstractC3169i5.f(c0814p).J0, "right_pill_label", null, AbstractC3169i5.g(c0814p).g, null, null, c0814p, 3072, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_BACKWARD_COMPATIBILITY);
            androidx.compose.ui.node.B.s(c0814p, true, true, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.learn.checkpoint.ui.a(gVar2, qVar, i, 2, (byte) 0);
        }
    }

    public static final void c(com.quizlet.learn.ui.progress.g progressData, androidx.compose.ui.q qVar, int i, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        Intrinsics.checkNotNullParameter(progressData, "progressData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2120524568);
        int i4 = (c0814p.f(progressData) ? 4 : 2) | i2 | (c0814p.f(qVar) ? 32 : 16) | 128;
        if ((i4 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                i3 = i4 & (-897);
                i = AbstractC3205m5.g(c0814p).a;
            } else {
                c0814p.Q();
                i3 = i4 & (-897);
            }
            c0814p.q();
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            if (i == 0) {
                c0814p.X(2107949071);
                a(progressData, qVar, c0814p, i3 & 126);
                c0814p.p(false);
            } else {
                c0814p.X(2107950960);
                b(progressData, qVar, c0814p, i3 & 126);
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.learn.checkpoint.ui.a(progressData, qVar, i, i2);
        }
    }

    public static ArrayList d(Iterator it2) {
        ArrayList arrayList = new ArrayList();
        it2.getClass();
        while (it2.hasNext()) {
            arrayList.add(it2.next());
        }
        return arrayList;
    }

    public static AbstractList e(List list, Function function) {
        return list instanceof RandomAccess ? new C2673tu(list, function) : new C2716uu(list, function);
    }
}
