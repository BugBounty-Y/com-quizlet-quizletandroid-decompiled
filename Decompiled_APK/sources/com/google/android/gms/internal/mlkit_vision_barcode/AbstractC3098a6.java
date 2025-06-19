package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.a6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3098a6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(String title, String info, String buttonText, Function0 buttonOnClick, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar;
        boolean z;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(info, "info");
        Intrinsics.checkNotNullParameter(buttonText, "buttonText");
        Intrinsics.checkNotNullParameter(buttonOnClick, "buttonOnClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-172006800);
        int i3 = i | (c0814p.f(title) ? 4 : 2) | (c0814p.f(info) ? 32 : 16) | (c0814p.f(buttonText) ? 256 : 128) | (c0814p.h(buttonOnClick) ? 2048 : 1024) | 24576;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(nVar2, com.quizlet.ui.resources.designsystem.generated.j.i);
            C0380d c0380d = AbstractC0398m.a;
            mVar.s();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h), androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(-517118680);
            if (StringsKt.O(title)) {
                i2 = i3;
                nVar = nVar2;
                z = false;
            } else {
                i2 = i3;
                nVar = nVar2;
                androidx.compose.material3.Q4.b(title, androidx.compose.foundation.layout.K0.c(nVar2, 1.0f), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).i, c0814p, (i3 & 14) | 48, 0, 65528);
                c0814p = c0814p;
                z = false;
            }
            c0814p.p(z);
            androidx.compose.foundation.N0 scrollState = AbstractC0460p.r(c0814p);
            androidx.compose.ui.n nVar3 = nVar;
            androidx.compose.ui.q scrollVerticalFadingEdges = AbstractC0460p.u(androidx.compose.foundation.layout.K0.c(nVar3, 1.0f), scrollState, z, 14);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jN = ((com.quizlet.themes.b) c0814p.j(b)).b.n();
            Intrinsics.checkNotNullParameter(scrollVerticalFadingEdges, "$this$scrollVerticalFadingEdges");
            Intrinsics.checkNotNullParameter(scrollState, "scrollState");
            androidx.compose.ui.q qVarF = M5.f(scrollVerticalFadingEdges, scrollState, jN, com.quizlet.themes.m.n);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException("invalid weight 1.0; must be greater than zero".toString());
            }
            int i5 = i2 >> 3;
            C0814p c0814p2 = c0814p;
            androidx.compose.material3.Q4.b(info, qVarF.g(new LayoutWeightElement(1.0f, z)), ((com.quizlet.themes.b) c0814p.j(b)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, androidx.compose.ui.text.L.b(((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).o, 0L, 0L, null, null, 0L, 0, 0L, null, 16711679), c0814p2, i5 & 14, 0, 65528);
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.Y4.b(buttonText, androidx.compose.foundation.layout.K0.c(nVar3, 1.0f), buttonOnClick, false, null, null, 0L, 0L, null, null, null, c0814p, ((i2 >> 6) & 14) | 48 | (i5 & 896), 0, 4088);
            c0814p.p(true);
            qVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(title, info, buttonText, buttonOnClick, qVar2, i);
        }
    }

    public static final void b(androidx.constraintlayout.compose.k kVar, List list) {
        int size = list.size();
        for (int i = 0; i < size; i++) {
            androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) list.get(i);
            Object objH = AbstractC0897s.h(j);
            if (objH == null) {
                j.G();
                objH = new com.google.firebase.heartbeatinfo.e(3);
            }
            androidx.constraintlayout.core.state.b bVarB = kVar.b(objH.toString());
            if (bVarB != null) {
                bVarB.f0 = j;
                androidx.constraintlayout.core.widgets.e eVar = bVarB.g0;
                if (eVar != null) {
                    eVar.i0 = j;
                }
            }
            j.G();
        }
    }
}
