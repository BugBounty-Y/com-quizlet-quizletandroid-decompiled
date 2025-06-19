package com.google.mlkit.vision.common.internal;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.B;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.U;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.D;
import androidx.compose.ui.text.L;
import androidx.compose.ui.text.font.j;
import androidx.compose.ui.text.font.q;
import androidx.compose.ui.text.font.r;
import androidx.compose.ui.text.font.u;
import androidx.compose.ui.text.style.o;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.R4;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.f;
import com.quizlet.themes.g;
import com.quizlet.themes.m;
import com.quizlet.themes.w;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class c {
    public static final /* synthetic */ int a = 0;

    public static final void a(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1496712492);
        int i2 = i | (c0814p.h(function0) ? 32 : 16);
        if ((i2 & 17) == 16 && c0814p.x()) {
            c0814p.Q();
        } else {
            String strD = AbstractC3106b5.d(c0814p, R.string.content_limited_limit_hit);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.content_limited_clickable_text);
            String strC = AbstractC3106b5.c(R.string.content_limited_contact, new Object[]{strD2}, c0814p);
            c0814p.X(213037377);
            C0984d c0984d = new C0984d();
            B b = g.a;
            int i3 = c0984d.i(new D(((com.quizlet.themes.b) c0814p.j(b)).b.e(), 0L, (u) null, (q) null, (r) null, (j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (U) null, 65534));
            try {
                c0984d.f(strC);
                Unit unit = Unit.a;
                c0984d.h(i3);
                c0984d.c(new D(((com.quizlet.themes.b) c0814p.j(b)).e, 0L, (u) null, (q) null, (r) null, (j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (U) null, 65534), StringsKt.M(strC, strD2, 0, false, 6), strD2.length() + StringsKt.M(strC, strD2, 0, false, 6));
                c0984d.b("helpCenter", StringsKt.M(strC, strD2, 0, false, 6), "helpCenter", strD2.length() + StringsKt.M(strC, strD2, 0, false, 6));
                C0995g c0995gJ = c0984d.j();
                c0814p.p(false);
                B b2 = w.a;
                L l = ((f) c0814p.j(b2)).o;
                n nVar = n.b;
                m mVar = m.g;
                mVar.q();
                Q4.b(strD, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65532);
                c0814p = c0814p;
                L l2 = ((f) c0814p.j(b2)).o;
                mVar.s();
                androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
                c0814p.X(213070272);
                boolean zF = c0814p.f(c0995gJ) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
                Object objI = c0814p.I();
                if (zF || objI == C0804k.a) {
                    z = false;
                    objI = new com.quizlet.explanations.solution.solutionwall.limitedcontent.a(c0995gJ, function0, 0);
                    c0814p.i0(objI);
                } else {
                    z = false;
                }
                c0814p.p(z);
                AbstractC0484d0.c(c0995gJ, qVarY, l2, false, 0, 0, null, (Function1) objI, c0814p, 0);
            } catch (Throwable th) {
                c0984d.h(i3);
                throw th;
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.solutionwall.limitedcontent.b(i, 0, function0);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2116043421);
        if ((((c0814p.f(qVar) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            R4.a(null, null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(1317093539, new com.quizlet.explanations.questiondetail.ui.composables.m(1, function0), c0814p), c0814p, 0, 1023);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.b(qVar, function0, i, 1);
        }
    }
}
