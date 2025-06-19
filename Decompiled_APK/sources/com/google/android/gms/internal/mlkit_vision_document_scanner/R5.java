package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class R5 {
    public static final /* synthetic */ int a = 0;

    public static final void a(String body, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(body, "body");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-807869098);
        int i2 = i | (c0814p2.f(body) ? 4 : 2) | 48;
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).o;
            c0814p = c0814p2;
            nVar2 = nVar3;
            androidx.compose.material3.Q4.b(body, nVar2, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, i2 & 126, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.modals.e(body, nVar2, i, 1);
        }
    }

    public static final void b(String title, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(title, "title");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-593875974);
        int i2 = i | (c0814p2.f(title) ? 4 : 2) | 48;
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).e;
            c0814p = c0814p2;
            nVar2 = nVar3;
            androidx.compose.material3.Q4.b(title, nVar2, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, i2 & 126, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.modals.e(title, nVar2, i, 0);
        }
    }
}
