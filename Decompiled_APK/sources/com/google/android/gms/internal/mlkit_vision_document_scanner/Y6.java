package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Y6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(final com.quizlet.uicommon.ui.common.util.d primaryStepData, com.quizlet.uicommon.ui.common.util.d secondaryStepData, final Function1 onPrimaryStepClick, final Function1 onSecondaryStepClick, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        final com.quizlet.uicommon.ui.common.util.d dVar;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(primaryStepData, "primaryStepData");
        Intrinsics.checkNotNullParameter(secondaryStepData, "secondaryStepData");
        Intrinsics.checkNotNullParameter(onPrimaryStepClick, "onPrimaryStepClick");
        Intrinsics.checkNotNullParameter(onSecondaryStepClick, "onSecondaryStepClick");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(735040119);
        int i2 = i | (c0814p2.f(primaryStepData) ? 4 : 2) | (c0814p2.f(secondaryStepData) ? 32 : 16) | (c0814p2.h(onPrimaryStepClick) ? 256 : 128) | (c0814p2.h(onSecondaryStepClick) ? 2048 : 1024) | (c0814p2.f(qVar) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            dVar = secondaryStepData;
        } else {
            androidx.compose.runtime.X0 x0 = AndroidCompositionLocals_androidKt.b;
            com.quizlet.uicommon.ui.common.util.e eVarA = com.google.firebase.b.a(primaryStepData, (Context) c0814p2.j(x0), true);
            com.quizlet.uicommon.ui.common.util.e eVarA2 = com.google.firebase.b.a(secondaryStepData, (Context) c0814p2.j(x0), false);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, bA, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h);
            }
            C0776c.E(c0814p2, qVarC2, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p2, R.string.test_result_next_steps);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).g;
            long jF = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.f();
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.material3.Q4.b(strD, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, ((Context) c0814p2.j(x0)).getResources().getDimension(R.dimen.quizlet_edge_margin) / ((androidx.compose.ui.unit.b) c0814p2.j(AbstractC0955m0.f)).a(), DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jF, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p2, 0, 0, 65528);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            AbstractC0382e.f(c0814p2, androidx.compose.foundation.layout.K0.d(nVar, f));
            C4097w c4097w = C4097w.a;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(nVar, 1.0f), "primaryStep");
            androidx.compose.ui.graphics.painter.b bVarB = b(eVarA, c0814p2);
            c0814p2.X(-1847927929);
            boolean z = ((i2 & 896) == 256) | ((i2 & 14) == 4);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                final int i4 = 0;
                objI = new Function0() { // from class: com.quizlet.quizletandroid.ui.studymodes.testmode.compose.o
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i4) {
                            case 0:
                                onPrimaryStepClick.invoke(primaryStepData);
                                break;
                            default:
                                onPrimaryStepClick.invoke(primaryStepData);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            W4.a(eVarA.a, qVarG, (Function0) objI, false, null, c4097w, null, bVarB, null, false, c0814p2, 805306416, 344);
            mVar.s();
            AbstractC0382e.f(c0814p2, androidx.compose.foundation.layout.K0.d(nVar, f));
            androidx.compose.ui.q qVarG2 = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(nVar, 1.0f), "secondaryStep");
            androidx.compose.ui.graphics.painter.b bVarB2 = b(eVarA2, c0814p2);
            c0814p2.X(-1847913013);
            boolean z2 = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i2 & 7168) == 2048);
            Object objI2 = c0814p2.I();
            if (z2 || objI2 == v) {
                final int i5 = 1;
                dVar = secondaryStepData;
                objI2 = new Function0() { // from class: com.quizlet.quizletandroid.ui.studymodes.testmode.compose.o
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i5) {
                            case 0:
                                onSecondaryStepClick.invoke(dVar);
                                break;
                            default:
                                onSecondaryStepClick.invoke(dVar);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(objI2);
            } else {
                dVar = secondaryStepData;
            }
            c0814p2.p(false);
            Y4.a(eVarA2.a, qVarG2, (Function0) objI2, false, false, null, null, 0L, 0L, c4097w, bVarB2, null, false, c0814p2, 48, 384, 2552);
            c0814p = c0814p2;
            mVar.w();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, com.quizlet.ui.resources.designsystem.generated.j.f));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(primaryStepData, dVar, onPrimaryStepClick, onSecondaryStepClick, qVar, i);
        }
    }

    public static final androidx.compose.ui.graphics.painter.b b(com.quizlet.uicommon.ui.common.util.e eVar, InterfaceC0806l interfaceC0806l) {
        androidx.compose.ui.graphics.painter.b bVarA;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1409392008);
        if (eVar.d == com.quizlet.data.model.A0.a) {
            c0814p.X(-1679456933);
            bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_legacy_locked_pill_yellow, c0814p, 0);
            c0814p.p(false);
        } else {
            c0814p.X(-1679359407);
            bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(eVar.c, c0814p, 0);
            c0814p.p(false);
        }
        c0814p.p(false);
        return bVarA;
    }
}
