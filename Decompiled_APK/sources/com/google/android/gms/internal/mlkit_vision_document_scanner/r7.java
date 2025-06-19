package com.google.android.gms.internal.mlkit_vision_document_scanner;

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
import androidx.navigation.compose.C1280m;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class r7 {
    public static com.google.android.gms.internal.mlkit_common.r a;
    public static final /* synthetic */ int b = 0;

    public static final void a(com.quizlet.explanations.questiondetail.data.e state, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(486661091);
        if ((((c0814p.h(state) ? 4 : 2) | i | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
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
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            com.google.common.util.concurrent.b.b(0, 0, c0814p, AbstractC0382e.y(nVar, f2, f, f2, DefinitionKt.NO_Float_VALUE, 8), state.d);
            c0814p.X(-169643005);
            if (state.a.isEmpty()) {
                qVar = nVar;
            } else {
                mVar.q();
                qVar = nVar;
                com.google.common.util.concurrent.a.a(state.a, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), state.c, state.b, c0814p, 0);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(state, qVar, i, 7);
        }
    }

    public static synchronized p7 b() {
        p7 p7Var;
        byte b2 = (byte) (((byte) 1) | 2);
        if (b2 != 3) {
            StringBuilder sb = new StringBuilder();
            if ((b2 & 1) == 0) {
                sb.append(" enableFirelog");
            }
            if ((b2 & 2) == 0) {
                sb.append(" firelogEventType");
            }
            throw new IllegalStateException("Missing required properties:".concat(sb.toString()));
        }
        m7 m7Var = new m7();
        synchronized (r7.class) {
            try {
                if (a == null) {
                    a = new com.google.android.gms.internal.mlkit_common.r(4);
                }
                p7Var = (p7) a.p(m7Var);
            } catch (Throwable th) {
                throw th;
            }
        }
        return p7Var;
        return p7Var;
    }
}
