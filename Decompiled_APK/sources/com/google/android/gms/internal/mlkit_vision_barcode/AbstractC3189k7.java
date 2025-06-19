package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.C0367i0;
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
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import com.quizlet.features.folders.composables.C4261q;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.k7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3189k7 {
    public static final void a(String str, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-508823149);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(str) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(dVar) ? 256 : 128;
        }
        int i3 = i2 | 3072;
        if ((i3 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p2, 48);
            int i4 = c0814p2.P;
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
            C0776c.E(c0814p2, g0B, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.material3.Q4.b(str, androidx.compose.ui.draw.g.h(androidx.compose.ui.n.b, Z4.a(((com.quizlet.themes.c) c0814p2.j(com.quizlet.themes.n.a)).a(), c0814p2, 0), null, C0888i.g, DefinitionKt.NO_Float_VALUE, null, 54), ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).i, c0814p2, i3 & 14, 0, 65528);
            c0814p = c0814p2;
            c0814p.X(722025110);
            c0814p.p(false);
            c0814p.X(722035361);
            if (dVar != null) {
                if (1.0f <= 0.0d) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
                }
                AbstractC0382e.f(c0814p, new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true));
                dVar.invoke(c0814p, Integer.valueOf((i3 >> 6) & 14));
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 18, str, qVar, dVar);
        }
    }

    public static final void b(String title, androidx.compose.ui.q qVar, String str, Function0 function0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        Intrinsics.checkNotNullParameter(title, "title");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2064428034);
        if ((i & 6) == 0) {
            i3 = (c0814p.f(title) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.f(qVar) ? 32 : 16;
        }
        int i4 = i2 & 4;
        if (i4 != 0) {
            i3 |= 384;
        } else if ((i & 384) == 0) {
            i3 |= c0814p.f(str) ? 256 : 128;
        }
        int i5 = i2 & 8;
        if (i5 != 0) {
            i3 |= 3072;
        } else if ((i & 3072) == 0) {
            i3 |= c0814p.h(function0) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i4 != 0) {
                str = null;
            }
            if (i5 != 0) {
                c0814p.X(573378555);
                Object objI = c0814p.I();
                if (objI == C0804k.a) {
                    objI = new com.quizlet.features.emailconfirmation.ui.composables.c(22);
                    c0814p.i0(objI);
                }
                function0 = (Function0) objI;
                c0814p.p(false);
            }
            a(title, qVar, androidx.compose.runtime.internal.e.e(-319312155, new C4261q(str, function0, 1), c0814p), c0814p, (i3 & ContentType.LONG_FORM_ON_DEMAND) | (i3 & 14) | 384);
        }
        String str2 = str;
        Function0 function02 = function0;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.F(title, qVar, str2, function02, i, i2, 5);
        }
    }

    public static final void c(androidx.glance.a aVar, String str, androidx.glance.p pVar, int i, androidx.glance.f fVar, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        int i4;
        androidx.glance.p pVarC;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(491792371);
        int i5 = (c0814p.f(aVar) ? 4 : 2) | i2 | (c0814p.f(str) ? 32 : 16) | (c0814p.f(pVar) ? 256 : 128);
        int i6 = i5 | 3072;
        int i7 = i3 & 16;
        if (i7 != 0) {
            i4 = i5 | 27648;
        } else {
            int i8 = 32768 & i2;
            i4 = (c0814p.f(fVar) ? 16384 : 8192) | i6;
        }
        if ((i4 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i7 != 0) {
                fVar = null;
            }
            c0814p.Y(135631275);
            if (str != null) {
                c0814p.Y(135633130);
                boolean zF = c0814p.f(str);
                Object objI = c0814p.I();
                if (zF || objI == C0804k.a) {
                    objI = new C0367i0(str, 11);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                pVarC = AbstractC3340g.c(pVar, (Function1) objI);
            } else {
                pVarC = pVar;
            }
            c0814p.p(false);
            androidx.glance.q qVar = androidx.glance.q.a;
            c0814p.Y(-1115894518);
            c0814p.Y(1886828752);
            if (!(c0814p.a instanceof androidx.glance.b)) {
                C0776c.s();
                throw null;
            }
            c0814p.V();
            if (c0814p.O) {
                c0814p.k(new androidx.compose.ui.input.nestedscroll.b(qVar));
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, aVar, androidx.glance.g.c);
            C0776c.E(c0814p, pVarC, androidx.glance.g.d);
            C0776c.E(c0814p, new androidx.glance.layout.h(), androidx.glance.g.e);
            C0776c.E(c0814p, fVar, androidx.glance.g.f);
            i = 1;
            c0814p.p(true);
            c0814p.p(false);
            c0814p.p(false);
        }
        int i9 = i;
        androidx.glance.f fVar2 = fVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.glance.r(aVar, str, pVar, i9, fVar2, i2, i3);
        }
    }

    public static final org.slf4j.b d(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        org.slf4j.b bVarD = org.slf4j.d.d(name);
        Intrinsics.checkNotNullExpressionValue(bVarD, "getLogger(...)");
        return bVarD;
    }

    public static final boolean e(androidx.glance.l lVar) {
        String str = null;
        androidx.glance.semantics.b bVar = (androidx.glance.semantics.b) lVar.a.a(null, androidx.glance.g.g);
        androidx.glance.semantics.a aVar = bVar != null ? bVar.a : null;
        if (aVar != null) {
            Object obj = aVar.a.get(androidx.glance.semantics.d.a);
            if (obj == null) {
                obj = null;
            }
            List list = (List) obj;
            if (list != null) {
                str = (String) list.get(0);
            }
        }
        return str == null || str.length() == 0;
    }
}
