package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.graphics.C0848h;
import androidx.compose.ui.graphics.vector.C0867f;
import androidx.compose.ui.layout.InterfaceC0889j;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0976x0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import coil3.compose.internal.ContentPainterElement;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3155h0;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableText;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class p3 {
    public static final void a(coil3.compose.internal.a aVar, String str, androidx.compose.ui.q qVar, Function1 function1, Function1 function12, androidx.compose.ui.d dVar, InterfaceC0889j interfaceC0889j, AbstractC0874w abstractC0874w, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        Function1 function13;
        Function1 function14;
        androidx.compose.ui.d dVar2;
        int i4;
        coil3.request.g gVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1236588022);
        if ((i & 6) == 0) {
            i3 = (c0814p.f(aVar) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.f(str) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            function13 = function1;
            i3 |= c0814p.h(function13) ? 2048 : 1024;
        } else {
            function13 = function1;
        }
        if ((i & 24576) == 0) {
            function14 = function12;
            i3 |= c0814p.h(function14) ? 16384 : 8192;
        } else {
            function14 = function12;
        }
        if ((196608 & i) == 0) {
            dVar2 = dVar;
            i3 |= c0814p.f(dVar2) ? 131072 : 65536;
        } else {
            dVar2 = dVar;
        }
        if ((1572864 & i) == 0) {
            i3 |= c0814p.f(interfaceC0889j) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i3 |= c0814p.c(1.0f) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i3 |= c0814p.f(abstractC0874w) ? 67108864 : 33554432;
        }
        if ((805306368 & i) == 0) {
            i3 |= c0814p.d(1) ? 536870912 : 268435456;
        }
        if ((i2 & 6) == 0) {
            i4 = i2 | (c0814p.g(true) ? 4 : 2);
        } else {
            i4 = i2;
        }
        if ((i3 & 306783379) == 306783378 && (i4 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i5 = coil3.compose.internal.g.b;
            c0814p.X(-329318062);
            Object obj = aVar.a;
            boolean z = obj instanceof coil3.request.g;
            Object obj2 = C0804k.a;
            if (z) {
                c0814p.X(-858608894);
                gVar = (coil3.request.g) obj;
                if (gVar.s.g != null) {
                    c0814p.X(-858568842);
                    c0814p.p(false);
                    c0814p.p(false);
                    c0814p.p(false);
                } else {
                    c0814p.X(-858520668);
                    coil3.size.i iVarA = coil3.compose.internal.g.a(interfaceC0889j, c0814p);
                    boolean zF = c0814p.f(gVar) | c0814p.f(iVarA);
                    Object objI = c0814p.I();
                    if (zF || objI == obj2) {
                        coil3.request.d dVarA = coil3.request.g.a(gVar);
                        dVarA.l = iVarA;
                        objI = dVarA.a();
                        c0814p.i0(objI);
                    }
                    gVar = (coil3.request.g) objI;
                    androidx.compose.ui.node.B.s(c0814p, false, false, false);
                }
            } else {
                c0814p.X(-858262500);
                Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
                coil3.size.i iVarA2 = coil3.compose.internal.g.a(interfaceC0889j, c0814p);
                boolean zF2 = c0814p.f(context) | c0814p.f(obj) | c0814p.f(iVarA2);
                Object objI2 = c0814p.I();
                if (zF2 || objI2 == obj2) {
                    coil3.request.d dVar3 = new coil3.request.d(context);
                    dVar3.c = obj;
                    dVar3.l = iVarA2;
                    objI2 = dVar3.a();
                    c0814p.i0(objI2);
                }
                gVar = (coil3.request.g) objI2;
                c0814p.p(false);
                c0814p.p(false);
            }
            coil3.request.g gVar2 = gVar;
            Object obj3 = gVar2.b;
            if (obj3 instanceof coil3.request.d) {
                throw new IllegalArgumentException("Unsupported type: ImageRequest.Builder. Did you forget to call ImageRequest.Builder.build()?");
            }
            coil3.compose.m mVar = null;
            if (obj3 instanceof C0848h) {
                coil3.compose.internal.g.b("ImageBitmap");
                throw null;
            }
            if (obj3 instanceof C0867f) {
                coil3.compose.internal.g.b("ImageVector");
                throw null;
            }
            if (obj3 instanceof androidx.compose.ui.graphics.painter.b) {
                coil3.compose.internal.g.b("Painter");
                throw null;
            }
            if (gVar2.c != null) {
                throw new IllegalArgumentException("request.target must be null.");
            }
            if (((androidx.lifecycle.C) coil3.n.d(gVar2, coil3.request.i.e)) != null) {
                throw new IllegalArgumentException("request.lifecycle must be null.");
            }
            if (((Boolean) c0814p.j(AbstractC0976x0.a)).booleanValue()) {
                c0814p.X(-1358303232);
                mVar = (coil3.compose.m) c0814p.j(coil3.compose.s.a);
                c0814p.p(false);
            } else {
                c0814p.X(-1358245727);
                c0814p.p(false);
            }
            androidx.compose.ui.q qVarG = qVar.g(new ContentPainterElement(gVar2, aVar.c, aVar.b, function13, function14, dVar2, interfaceC0889j, abstractC0874w, mVar, str));
            coil3.compose.internal.f fVar = coil3.compose.internal.f.a;
            int i6 = c0814p.P;
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            InterfaceC0915k.D0.getClass();
            Function0 function0 = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(function0);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, fVar, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h);
            }
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new coil3.compose.a(aVar, str, qVar, function1, function12, dVar, interfaceC0889j, abstractC0874w, i, i2);
        }
    }

    public static final void b(StudiableText text, StudiableAudio studiableAudio, androidx.compose.ui.q qVar, Function0 function0, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        StudiableAudio studiableAudio2;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1599177210);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(text) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            studiableAudio2 = studiableAudio;
            i2 |= c0814p.h(studiableAudio2) ? 32 : 16;
        } else {
            studiableAudio2 = studiableAudio;
        }
        int i3 = i2 | 384;
        if ((i & 3072) == 0) {
            i3 |= c0814p.h(function0) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p.h(function1) ? 16384 : 8192;
        }
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            qVar2 = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p, 48);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar2);
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
            androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.C.a(androidx.compose.ui.platform.N.G(qVar2, "textView"), 1.0f).g(androidx.compose.foundation.layout.K0.c);
            com.quizlet.themes.m.g.p();
            AbstractC3155h0.a(text.a, text.c, text.b, androidx.compose.foundation.layout.K0.r(androidx.compose.foundation.layout.K0.t(AbstractC0382e.u(qVarG, com.quizlet.ui.resources.designsystem.generated.j.j), 3), 3), DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, 0, 2, null, null, c0814p, 805306374, 3552);
            int i5 = i3 & ContentType.LONG_FORM_ON_DEMAND;
            int i6 = i3 >> 3;
            c0814p = c0814p;
            k3.a(null, studiableAudio2, function0, function1, c0814p, i5 | (i6 & 896) | (i6 & 7168), 1);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(text, studiableAudio, qVar2, function0, function1, i, 11);
        }
    }
}
