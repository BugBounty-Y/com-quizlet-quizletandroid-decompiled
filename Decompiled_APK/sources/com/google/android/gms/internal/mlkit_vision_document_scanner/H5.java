package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.material3.AbstractC0669k0;
import androidx.compose.material3.AbstractC0696o3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class H5 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.compose.runtime.internal.d text, Function0 onClick, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, boolean z, com.quizlet.assembly.compose.menu.j jVar, androidx.compose.foundation.layout.A0 a0, androidx.compose.foundation.interaction.l lVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.foundation.interaction.l lVar2;
        androidx.compose.foundation.layout.A0 a02;
        androidx.compose.foundation.interaction.l lVar3;
        androidx.compose.foundation.layout.A0 a03;
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1119305838);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(text) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(onClick) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(dVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(dVar2) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.g(z) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.f(jVar) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= 4194304;
        }
        if (((i2 | 100663296) & 38347923) == 38347922 && c0814p.x()) {
            c0814p.Q();
            a03 = a0;
            lVar3 = lVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                c0814p.X(675174461);
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.q();
                float f = com.quizlet.ui.resources.designsystem.generated.j.i;
                mVar.u();
                float f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
                androidx.compose.foundation.layout.A0 a04 = new androidx.compose.foundation.layout.A0(f, f2, f, f2);
                Object objG = com.google.android.gms.measurement.internal.Z.g(572420063, c0814p, false);
                if (objG == C0804k.a) {
                    objG = androidx.compose.animation.d0.i(c0814p);
                }
                c0814p.p(false);
                lVar2 = (androidx.compose.foundation.interaction.l) objG;
                a02 = a04;
            } else {
                c0814p.Q();
                a02 = a0;
                lVar2 = lVar;
            }
            c0814p.q();
            androidx.compose.ui.q qVarT = AbstractC0382e.t(androidx.compose.foundation.layout.K0.b(androidx.compose.foundation.layout.K0.c(AbstractC0460p.k(qVar, lVar2, AbstractC0696o3.b(true), z, null, onClick, 24), 1.0f), DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.Z, 1), a02);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarT);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.runtime.B b = AbstractC0669k0.a;
            c0814p.X(785044080);
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(new C0861v(z ? jVar.a : jVar.b), c0814p);
            c0814p.p(false);
            C0776c.a(b.a(interfaceC0773a0D.getValue()), androidx.compose.runtime.internal.e.e(1111241398, new com.quizlet.assembly.compose.menu.l(dVar, dVar2, text, 0), c0814p), c0814p, 56);
            c0814p.p(true);
            lVar3 = lVar2;
            a03 = a02;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.k(text, onClick, qVar, dVar, dVar2, z, jVar, a03, lVar3, i);
        }
    }
}
