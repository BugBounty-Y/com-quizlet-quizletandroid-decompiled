package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.material3.AbstractC0594b4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.features.folders.composables.C4261q;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public abstract class J4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.compose.ui.n nVar, com.quizlet.features.infra.folder.create.data.h hVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        com.quizlet.features.infra.folder.create.data.h hVar2;
        androidx.compose.ui.n nVar3;
        com.quizlet.features.infra.folder.create.data.h hVar3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2146068934);
        if (((i | 22 | (c0814p.h(function0) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
            hVar3 = hVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                nVar2 = androidx.compose.ui.n.b;
                hVar2 = com.quizlet.features.infra.folder.create.data.h.a;
            } else {
                c0814p.Q();
                nVar2 = nVar;
                hVar2 = hVar;
            }
            c0814p.q();
            if (hVar2 == null) {
                throw com.google.android.gms.measurement.internal.Z.j(-1705009228, c0814p, false);
            }
            String strH = com.google.android.gms.measurement.internal.Z.h(c0814p, -1315256821, R.string.folder_onboarding_start_building, c0814p, false);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(AbstractC0382e.p(androidx.compose.animation.H.a(nVar2, null, 3), 1), 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarC, com.quizlet.ui.resources.designsystem.generated.j.i);
            long j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).f;
            mVar.c();
            AbstractC0594b4.a(qVarU, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.h), j, 0L, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, androidx.compose.runtime.internal.e.e(1555023871, new C4261q(strH, function0, 0), c0814p), c0814p, 12582912, 120);
            nVar3 = nVar2;
            hVar3 = hVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 20, nVar3, hVar3, function0);
        }
    }

    public static final InterfaceC0773a0 b(androidx.lifecycle.T t, Object obj, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
        Object objI = c0814p.I();
        androidx.compose.runtime.V v = C0804k.a;
        if (objI == v) {
            if (t.e != androidx.lifecycle.T.k) {
                obj = t.d();
            }
            objI = C0776c.z(obj);
            c0814p.i0(objI);
        }
        InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
        boolean zH = c0814p.h(t) | c0814p.h(j);
        Object objI2 = c0814p.I();
        if (zH || objI2 == v) {
            objI2 = new androidx.activity.compose.g(t, j, interfaceC0773a0, 20);
            c0814p.i0(objI2);
        }
        C0776c.c(t, j, (Function1) objI2, c0814p);
        return interfaceC0773a0;
    }
}
