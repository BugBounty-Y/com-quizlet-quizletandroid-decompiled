package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_common.M2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.V5;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.assembly.compose.buttons.C4078c;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class M2 {
    public static final void a(final Function0 onDismiss, final long j, final androidx.compose.ui.graphics.painter.b imagePainter, final String title, final Function0 onCloseClick, final String buttonText, final Function0 onButtonClick, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        long j2;
        C0814p c0814p;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        Intrinsics.checkNotNullParameter(onDismiss, "onDismiss");
        Intrinsics.checkNotNullParameter(imagePainter, "imagePainter");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(onCloseClick, "onCloseClick");
        Intrinsics.checkNotNullParameter(buttonText, "buttonText");
        Intrinsics.checkNotNullParameter(onButtonClick, "onButtonClick");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1779511796);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(onDismiss) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            j2 = j;
            i2 |= c0814p2.e(j2) ? 32 : 16;
        } else {
            j2 = j;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(imagePainter) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.f(title) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(onCloseClick) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.f(buttonText) ? 131072 : 65536;
        }
        if ((i & 1572864) == 0) {
            i2 |= c0814p2.h(onButtonClick) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p2.f(nVar) ? 8388608 : 4194304;
        }
        int i3 = i2;
        if ((4793491 & i3) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            V5.a(nVar, null, false, null, onDismiss, null, androidx.compose.runtime.internal.e.e(-1605944160, new com.features.flashcards.creatormarketing.c(onCloseClick, j2, imagePainter, title, buttonText, onButtonClick), c0814p2), c0814p, ((i3 >> 21) & 14) | 1572864 | ((i3 << 12) & 57344), 46);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.features.flashcards.creatormarketing.a
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    String str = buttonText;
                    Function0 function0 = onButtonClick;
                    M2.a(onDismiss, j, imagePainter, title, onCloseClick, str, function0, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1239955521);
        int i2 = (c0814p.f(qVar) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            C4078c c4078c = new C4078c(((com.quizlet.themes.b) c0814p.j(b)).b.g(), ((com.quizlet.themes.b) c0814p.j(b)).b.f(), ((com.quizlet.themes.b) c0814p.j(b)).A(), ((com.quizlet.themes.b) c0814p.j(b)).b.b(), ((com.quizlet.themes.b) c0814p.j(b)).t, 32);
            ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
            com.google.android.gms.internal.mlkit_vision_document_scanner.V4.a(com.quizlet.ui.resources.icons.d.u(c0814p), AbstractC3106b5.d(c0814p, R.string.close), c4078c, qVar, function0, false, C4076a.e, null, AbstractC0460p.a(((com.quizlet.themes.b) c0814p.j(b)).t, com.quizlet.themes.m.l), c0814p, (i2 << 9) & 64512, 672);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.b(qVar, function0, i, 0);
        }
    }

    public static final void c(String title, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(title, "title");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-733936679);
        int i2 = i | (c0814p2.f(title) ? 4 : 2) | 48;
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).k;
            c0814p = c0814p2;
            nVar2 = nVar3;
            androidx.compose.material3.Q4.b(title, nVar2, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, i2 & 126, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.modals.e(title, nVar2, i, 2);
        }
    }
}
