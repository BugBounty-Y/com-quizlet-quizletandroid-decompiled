package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.foundation.layout.HorizontalAlignElement;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.i0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3164i0 {
    /* JADX WARN: Type inference failed for: r0v18, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.o] */
    /* JADX WARN: Type inference failed for: r7v15, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.o] */
    /* JADX WARN: Type inference failed for: r7v18, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.o] */
    public static final void a(com.quizlet.features.flashcards.data.q state, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        androidx.compose.ui.graphics.painter.b bVar;
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1957317031);
        int i2 = i | (c0814p.h(state) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            C0386g c0386g = AbstractC0398m.g;
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(c0386g, hVar, c0814p, 54);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarY);
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
            C0776c.E(c0814p, qVarC2, c0912h4);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true);
            String strE = AbstractC3053s1.e(state.i, (Context) c0814p.j(AndroidCompositionLocals_androidKt.b));
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b(strE, layoutWeightElement, jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).f, c0814p, 0, 0, 65528);
            mVar.o();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.o(nVar, com.quizlet.ui.resources.designsystem.generated.j.p));
            com.google.android.gms.internal.ads.N n = state.j;
            AbstractC0460p.c(Z4.a(n.a, c0814p, 0), null, null, null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 124);
            c0814p.p(true);
            mVar.p();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, com.quizlet.ui.resources.designsystem.generated.j.j));
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.flashcards_summary_your_progress), null, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).g, c0814p, 0, 0, 65530);
            mVar.q();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, f));
            AbstractC3182k0.e(state.h, null, c0814p, 8);
            mVar.q();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, f));
            AbstractC3586b5.a(AbstractC3106b5.d(c0814p, R.string.flashcards_rounds_back), androidx.compose.foundation.layout.K0.c(nVar, 1.0f).g(new HorizontalAlignElement(androidx.compose.ui.b.n)), function0, state.g, null, null, null, null, null, c0814p, i2 & 896, 1008);
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.C.a(nVar, 1.0f));
            c0814p.X(2083778042);
            androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            com.quizlet.features.flashcards.data.n nVar2 = (com.quizlet.features.flashcards.data.n) n.b;
            String strD = AbstractC3106b5.d(c0814p, nVar2.a);
            c0814p.X(2083786675);
            Function2 function2 = nVar2.d;
            if (function2 == null) {
                bVar = null;
                z = false;
            } else {
                z = false;
                bVar = (androidx.compose.ui.graphics.painter.b) function2.invoke(c0814p, 0);
            }
            c0814p.p(z);
            com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(strD, qVarC3, nVar2.b, false, null, null, nVar2.c, bVar, null, false, c0814p, 48, 824);
            c0814p.X(2083790325);
            com.quizlet.features.flashcards.data.n nVar3 = (com.quizlet.features.flashcards.data.n) n.c;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, f2));
            com.google.android.gms.internal.mlkit_vision_document_scanner.Y4.b(AbstractC3106b5.d(c0814p, nVar3.a), androidx.compose.foundation.layout.K0.c(nVar, 1.0f), nVar3.b, false, null, null, 0L, 0L, null, null, null, c0814p, 48, 0, 4088);
            c0814p = c0814p;
            Unit unit = Unit.a;
            c0814p.p(false);
            c0814p.X(2083801840);
            com.quizlet.features.flashcards.data.n nVar4 = (com.quizlet.features.flashcards.data.n) n.d;
            if (nVar4 != null) {
                mVar.s();
                AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, f2));
                AbstractC3586b5.a(AbstractC3106b5.d(c0814p, nVar4.a), androidx.compose.foundation.layout.K0.c(nVar, 1.0f), nVar4.b, false, null, null, null, null, null, c0814p, 48, 1016);
            }
            c0814p.p(false);
            c0814p.p(false);
            mVar.q();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, f));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 16, state, qVar, function0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:165:0x024d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(androidx.compose.ui.q r35, androidx.compose.foundation.lazy.grid.A r36, androidx.compose.foundation.lazy.grid.C0428c r37, androidx.compose.foundation.layout.A0 r38, androidx.compose.foundation.gestures.C0343p r39, boolean r40, androidx.compose.foundation.layout.InterfaceC0394k r41, androidx.compose.foundation.layout.InterfaceC0388h r42, kotlin.jvm.functions.Function1 r43, androidx.compose.runtime.InterfaceC0806l r44, int r45, int r46) {
        /*
            Method dump skipped, instructions count: 868
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3164i0.b(androidx.compose.ui.q, androidx.compose.foundation.lazy.grid.A, androidx.compose.foundation.lazy.grid.c, androidx.compose.foundation.layout.A0, androidx.compose.foundation.gestures.p, boolean, androidx.compose.foundation.layout.k, androidx.compose.foundation.layout.h, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:106:0x0161  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0165  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0175  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x0189  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x018d  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0190  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0195  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x01b9  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x01dd  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x0215  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x0241  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x024a  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x024d  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x026d  */
    /* JADX WARN: Removed duplicated region for block: B:168:0x039a  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x03bd  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x03c0  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x03ca  */
    /* JADX WARN: Removed duplicated region for block: B:180:0x041f  */
    /* JADX WARN: Removed duplicated region for block: B:189:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0082  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0096  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00a1  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00bd  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00c8  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00d4  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00fb  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0118  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(final boolean r58, final java.lang.String r59, final java.lang.String r60, final java.lang.String r61, final androidx.compose.ui.q r62, androidx.compose.ui.text.L r63, long r64, int r66, int r67, com.quizlet.richtext.ui.f r68, kotlin.jvm.functions.Function1 r69, androidx.compose.runtime.InterfaceC0806l r70, final int r71, final int r72, final int r73) {
        /*
            Method dump skipped, instructions count: 1080
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3164i0.c(boolean, java.lang.String, java.lang.String, java.lang.String, androidx.compose.ui.q, androidx.compose.ui.text.L, long, int, int, com.quizlet.richtext.ui.f, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int, int):void");
    }
}
