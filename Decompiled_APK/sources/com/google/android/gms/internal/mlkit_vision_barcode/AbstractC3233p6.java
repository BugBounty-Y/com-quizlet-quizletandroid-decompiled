package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.os.UserManager;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0416v0;
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
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.p6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3233p6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(C0416v0 windowInsets, Function0 createSetCTAOnClick, boolean z, int i, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i2) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(windowInsets, "windowInsets");
        Intrinsics.checkNotNullParameter(createSetCTAOnClick, "createSetCTAOnClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-205625996);
        int i3 = i2 | (c0814p.f(windowInsets) ? 4 : 2) | (c0814p.h(createSetCTAOnClick) ? 32 : 16) | (c0814p.g(z) ? 256 : 128) | (c0814p.d(i) ? 2048 : 1024) | 24576;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            nVar2 = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0460p.u(nVar2, AbstractC0460p.r(c0814p), false, 14), "UpgradeConfirmationContent");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
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
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jL = ((com.quizlet.themes.b) c0814p.j(b)).L();
            com.quizlet.shared.usecase.folderstudymaterials.d dVar = androidx.compose.ui.graphics.F.a;
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(AbstractC0460p.f(nVar2, jL, dVar), 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarC2, f, DefinitionKt.NO_Float_VALUE, 2);
            mVar.q();
            androidx.compose.ui.q qVarB = androidx.compose.foundation.layout.U0.b(AbstractC0382e.y(qVarW, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), windowInsets);
            int i5 = i3 >> 6;
            AbstractC3224o6.a(z, qVarB, c0814p, i5 & 14);
            androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(AbstractC0460p.f(nVar2, ((com.quizlet.themes.b) c0814p.j(b)).b.g(), dVar), 1.0f);
            mVar.q();
            mVar.s();
            AbstractC3215n6.h(i, ((i3 >> 3) & 14) | (i5 & ContentType.LONG_FORM_ON_DEMAND), 0, c0814p, androidx.compose.foundation.layout.U0.b(AbstractC0382e.v(qVarC3, f, com.quizlet.ui.resources.designsystem.generated.j.h), windowInsets), createSetCTAOnClick);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.recyclerview.step.g(windowInsets, createSetCTAOnClick, z, i, nVar2, i2);
        }
    }

    public static boolean b(Context context) {
        return ((UserManager) context.getSystemService(UserManager.class)).isUserUnlocked();
    }
}
