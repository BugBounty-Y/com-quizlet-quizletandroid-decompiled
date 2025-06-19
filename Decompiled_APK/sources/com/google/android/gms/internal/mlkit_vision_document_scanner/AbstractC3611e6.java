package com.google.android.gms.internal.mlkit_vision_document_scanner;

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
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.e6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3611e6 {
    public static final void a(androidx.compose.ui.graphics.painter.b image, String description, String buttonText, androidx.compose.ui.q qVar, String str, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(image, "image");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(buttonText, "buttonText");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-285854805);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(image) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(description) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(buttonText) ? 256 : 128;
        }
        int i3 = i2 | 3072;
        if ((i & 24576) == 0) {
            i3 |= c0814p.f(str) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p.h(function0) ? 131072 : 65536;
        }
        int i4 = i3;
        if ((i4 & 74899) == 74898 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarU = AbstractC0460p.u(androidx.compose.foundation.layout.K0.c, AbstractC0460p.r(c0814p), false, 14);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.n, c0814p, 54);
            int i5 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.l();
            int i6 = i4 >> 9;
            AbstractC0460p.c(image, str, androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.k), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, (i4 & 14) | (i6 & ContentType.LONG_FORM_ON_DEMAND), 120);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).i;
            long jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
            mVar.s();
            androidx.compose.material3.Q4.b(description, androidx.compose.foundation.layout.K0.o(AbstractC0382e.u(nVar, com.quizlet.ui.resources.designsystem.generated.j.h), com.quizlet.themes.m.x), jE, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, (i4 >> 3) & 14, 0, 65016);
            mVar.t();
            W4.a(buttonText, AbstractC0382e.u(nVar, com.quizlet.ui.resources.designsystem.generated.j.k), function0, false, null, null, null, null, null, false, c0814p, ((i4 >> 6) & 14) | (i6 & 896), 1016);
            c0814p = c0814p;
            c0814p.p(true);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.screens.a(image, description, buttonText, qVar2, str, function0, i);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        androidx.compose.ui.q qVar2;
        Function0 onClick = function0;
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(729682602);
        int i2 = i | 6 | (c0814p.h(onClick) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarU = AbstractC0382e.u(nVar, f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p, 48);
            int i3 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            mVar.l();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.k), "lightbulb_image");
            com.quizlet.themes.e.a(c0814p).d.getClass();
            c0814p.X(-1217290406);
            androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_brand_lightbulb, c0814p, 0);
            c0814p.p(false);
            AbstractC0460p.c(bVarA, null, qVarG, null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 120);
            mVar.q();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, f));
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
            String strD = AbstractC3106b5.d(c0814p, R.string.push_notification_push_primer_title);
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b(strD, qVarC2, jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).e, c0814p, 48, 0, 65528);
            mVar.u();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, com.quizlet.ui.resources.designsystem.generated.j.g));
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.push_notification_push_primer_body), null, ((com.quizlet.themes.b) c0814p.j(b)).b.e(), 0L, null, 0L, new androidx.compose.ui.text.style.i(1), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).o, c0814p, 0, 0, 65018);
            c0814p = c0814p;
            mVar.p();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, com.quizlet.ui.resources.designsystem.generated.j.j));
            qVar2 = nVar;
            onClick = function0;
            W4.a(AbstractC3106b5.d(c0814p, R.string.got_it), androidx.compose.foundation.layout.K0.c(nVar, 1.0f), onClick, false, null, null, null, null, null, false, c0814p, ((i2 << 3) & 896) | 48, 1016);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.b(qVar2, onClick, i, 6);
        }
    }
}
