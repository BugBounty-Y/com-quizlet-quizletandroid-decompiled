package com.google.android.gms.internal.mlkit_vision_common;

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
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3642i5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class O2 {
    public static final void a(com.quizlet.features.settings.data.models.j jVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(341803143);
        if ((((c0814p.f(jVar) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            Integer num = jVar.b;
            c0814p.X(12979876);
            String strD = num == null ? null : AbstractC3106b5.d(c0814p, num.intValue());
            c0814p.p(false);
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
            M2.c(AbstractC3106b5.d(c0814p, R.string.manage_subscription_title), null, c0814p, 0);
            com.quizlet.themes.m.g.u();
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(259823191, new com.quizlet.assembly.compose.menu.l(jVar, strD, function0, 21), c0814p), c0814p, 0, 1022);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(jVar, function0, i, 9);
        }
    }

    public static final void b(com.quizlet.features.settings.data.models.k upgradeInfo, com.quizlet.data.repository.explanations.myexplanations.a actions, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(upgradeInfo, "upgradeInfo");
        Intrinsics.checkNotNullParameter(actions, "actions");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1211421984);
        if ((((c0814p.f(upgradeInfo) ? 4 : 2) | i | (c0814p.f(actions) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else if (upgradeInfo instanceof com.quizlet.features.settings.data.models.i) {
            c0814p.X(-610435061);
            AbstractC3642i5.a(((com.quizlet.features.settings.data.models.i) upgradeInfo).a, 0, c0814p, null, (Function0) actions.c);
            c0814p.p(false);
        } else {
            if (!(upgradeInfo instanceof com.quizlet.features.settings.data.models.j)) {
                throw com.google.android.gms.measurement.internal.Z.j(673043776, c0814p, false);
            }
            c0814p.X(673054527);
            a((com.quizlet.features.settings.data.models.j) upgradeInfo, (Function0) actions.b, c0814p, 0);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(upgradeInfo, actions, i, 8);
        }
    }
}
