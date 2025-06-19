package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3509p {
    public static volatile com.airbnb.lottie.network.d a;
    public static volatile com.airbnb.lottie.network.c b;

    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str, Function0 function0) {
        int i2;
        C0814p c0814p;
        Function0 function02;
        boolean z;
        String text = str;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(54369910);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(text) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function0) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            function02 = function0;
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            c0814p2.X(299201097);
            Object objI = c0814p2.I();
            if (objI == v) {
                objI = C0776c.z(Boolean.FALSE);
                c0814p2.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(299203112, c0814p2, false);
            if (objG == v) {
                objG = C0776c.z(Boolean.TRUE);
                c0814p2.i0(objG);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objG;
            c0814p2.p(false);
            int i3 = ((Boolean) interfaceC0773a0.getValue()).booleanValue() ? SubsamplingScaleImageView.TILE_SIZE_AUTO : 2;
            int i4 = ((Boolean) interfaceC0773a0.getValue()).booleanValue() ? R.string.show_less : R.string.show_more;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i5 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar);
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
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p2, i5, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "showMoreText");
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            long jE = ((com.quizlet.themes.b) c0814p2.j(b2)).b.e();
            androidx.compose.runtime.B b3 = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(b3)).p;
            c0814p2.X(770329777);
            Object objI2 = c0814p2.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a02, 15);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            int i6 = i4;
            int i7 = i2;
            text = str;
            androidx.compose.material3.Q4.b(text, qVarG, jE, 0L, null, 0L, null, 0L, 2, false, i3, 0, (Function1) objI2, l, c0814p2, (i2 & 14) | 48, 196656, 22520);
            c0814p = c0814p2;
            c0814p.X(770332151);
            if (((Boolean) interfaceC0773a02.getValue()).booleanValue() || ((Boolean) interfaceC0773a0.getValue()).booleanValue()) {
                c0814p.X(770335768);
                boolean z2 = (i7 & 896) == 256;
                Object objI3 = c0814p.I();
                if (z2 || objI3 == v) {
                    function02 = function0;
                    objI3 = new com.quizlet.features.blocks.ui.c(function02, interfaceC0773a0, 10);
                    c0814p.i0(objI3);
                } else {
                    function02 = function0;
                }
                c0814p.p(false);
                androidx.compose.ui.q qVarL = AbstractC0460p.l(nVar, false, null, (Function0) objI3, 7);
                z = true;
                androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, i6), qVarL, ((com.quizlet.themes.b) c0814p.j(b2)).e, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b3)).k, c0814p, 0, 0, 65528);
            } else {
                function02 = function0;
                z = true;
            }
            c0814p.p(false);
            c0814p.p(z);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.common.d(text, qVar, function02, i);
        }
    }
}
