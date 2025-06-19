package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.C0888i;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.i5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3642i5 {
    public static final /* synthetic */ int a = 0;

    public static final void a(int i, int i2, InterfaceC0806l interfaceC0806l, androidx.compose.ui.n nVar, Function0 onUpgradeClick) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(onUpgradeClick, "onUpgradeClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1475221796);
        int i3 = (c0814p.d(R.string.subscription_level_up_label) ? 4 : 2) | i2 | (c0814p.d(i) ? 32 : 16) | 384 | (c0814p.h(onUpgradeClick) ? 2048 : 1024);
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long j = ((com.quizlet.themes.b) c0814p.j(b)).v0;
            androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(AbstractC0460p.q(c0814p) ? R.drawable.bg_gradient_subscription_dark : R.drawable.bg_gradient_subscription_light, c0814p, 0);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.d();
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(androidx.compose.ui.draw.g.h(AbstractC0460p.f(androidx.compose.ui.draw.g.c(qVarC, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.g)), j, androidx.compose.ui.graphics.F.a), bVarA, androidx.compose.ui.b.f, C0888i.c, DefinitionKt.NO_Float_VALUE, null, 50), 1.0f);
            float f = com.quizlet.themes.m.P;
            mVar.s();
            androidx.compose.ui.q qVarV = AbstractC0382e.v(qVarC2, com.quizlet.ui.resources.designsystem.generated.j.h, f);
            c0814p.X(-296696726);
            boolean z = (i3 & 7168) == 2048;
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new com.braze.support.u(4, onUpgradeClick);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarL = AbstractC0460p.l(qVarV, false, null, (Function0) objI, 7);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g, androidx.compose.ui.b.k, c0814p, 54);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarL);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC3, C0914j.d);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            mVar.u();
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.subscription_level_up_label), AbstractC0382e.y(layoutWeightElement, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, 11), ((com.quizlet.themes.b) c0814p.j(b)).w0, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).g, c0814p, 0, 0, 65528);
            nVar2 = nVar3;
            b((i3 >> 3) & 896, 2, c0814p, null, AbstractC3106b5.d(c0814p, i), onUpgradeClick);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.e0(nVar2, onUpgradeClick, i, i2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0045  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0069  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00dc  */
    /* JADX WARN: Removed duplicated region for block: B:42:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(int r18, int r19, androidx.compose.runtime.InterfaceC0806l r20, androidx.compose.ui.q r21, java.lang.String r22, kotlin.jvm.functions.Function0 r23) {
        /*
            Method dump skipped, instructions count: 232
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3642i5.b(int, int, androidx.compose.runtime.l, androidx.compose.ui.q, java.lang.String, kotlin.jvm.functions.Function0):void");
    }
}
