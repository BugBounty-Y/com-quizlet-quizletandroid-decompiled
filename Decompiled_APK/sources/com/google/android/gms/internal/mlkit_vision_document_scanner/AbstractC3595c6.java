package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.AbstractC4707c;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.c6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3595c6 {
    public static final void a(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2039944310);
        int i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jG = ((com.quizlet.themes.b) c0814p.j(b)).G();
            long jU = ((com.quizlet.themes.b) c0814p.j(b)).u();
            com.quizlet.themes.e.a(c0814p).a.getClass();
            c0814p.X(-428518546);
            androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_sys_lock, c0814p, 0);
            c0814p.p(false);
            qVar2 = qVar;
            AbstractC3587b6.d(bVarA, qVar2, AbstractC3106b5.d(c0814p, R.string.lock), jU, jG, c0814p, (i2 << 3) & ContentType.LONG_FORM_ON_DEMAND, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 3, qVar2);
        }
    }

    public static final com.quizlet.quizletandroid.ui.startpage.nav2.model.u b(AbstractC4707c abstractC4707c) {
        Intrinsics.checkNotNullParameter(abstractC4707c, "<this>");
        if (abstractC4707c instanceof com.quizlet.quizletandroid.ui.startpage.nav2.model.E) {
            return com.quizlet.quizletandroid.ui.startpage.nav2.model.u.d;
        }
        if (abstractC4707c instanceof com.quizlet.quizletandroid.ui.startpage.nav2.model.C) {
            com.quizlet.quizletandroid.ui.startpage.nav2.model.C c = (com.quizlet.quizletandroid.ui.startpage.nav2.model.C) abstractC4707c;
            if (c instanceof com.quizlet.quizletandroid.ui.startpage.nav2.model.x) {
                return com.quizlet.quizletandroid.ui.startpage.nav2.model.u.a;
            }
            if (c instanceof com.quizlet.quizletandroid.ui.startpage.nav2.model.D) {
                return com.quizlet.quizletandroid.ui.startpage.nav2.model.u.b;
            }
            if (c instanceof com.quizlet.quizletandroid.ui.startpage.nav2.model.w) {
                return com.quizlet.quizletandroid.ui.startpage.nav2.model.u.c;
            }
            throw new NoWhenBranchMatchedException();
        }
        if (abstractC4707c instanceof com.quizlet.quizletandroid.ui.startpage.nav2.model.y) {
            return com.quizlet.quizletandroid.ui.startpage.nav2.model.u.e;
        }
        if (abstractC4707c instanceof com.quizlet.quizletandroid.ui.startpage.nav2.model.z) {
            return com.quizlet.quizletandroid.ui.startpage.nav2.model.u.f;
        }
        if (abstractC4707c instanceof com.quizlet.quizletandroid.ui.startpage.nav2.model.B) {
            return com.quizlet.quizletandroid.ui.startpage.nav2.model.u.h;
        }
        if (abstractC4707c instanceof com.quizlet.quizletandroid.ui.startpage.nav2.model.A) {
            return com.quizlet.quizletandroid.ui.startpage.nav2.model.u.g;
        }
        throw new IllegalStateException("The item of that type shouldn't exist: " + abstractC4707c);
    }
}
