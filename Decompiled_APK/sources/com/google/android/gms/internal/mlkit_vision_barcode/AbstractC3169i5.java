package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.i5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3169i5 {
    public static final void a(com.quizlet.data.model.v2 userProfileAvatarData, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(userProfileAvatarData, "userProfileAvatarData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1762814491);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(userProfileAvatarData) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i & 384) == 0) {
            i3 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            qVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(qVar, com.quizlet.themes.m.K0);
            androidx.compose.ui.i iVar = androidx.compose.ui.b.e;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarK);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0418x c0418x = C0418x.a;
            c0814p.X(-451061950);
            String str = userProfileAvatarData.b;
            androidx.compose.runtime.B b = com.quizlet.themes.e.a;
            ((com.quizlet.themes.d) c0814p.j(b)).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarA = com.quizlet.ui.resources.icons.d.A(c0814p);
            ((com.quizlet.themes.d) c0814p.j(b)).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarA2 = com.quizlet.ui.resources.icons.d.A(c0814p);
            mVar.j();
            com.google.android.gms.internal.mlkit_vision_camera.r3.b(str, userProfileAvatarData.a, AbstractC0460p.l(androidx.compose.ui.draw.g.c(c0418x.a(androidx.compose.foundation.layout.K0.k(qVar, com.quizlet.ui.resources.designsystem.generated.h.i), iVar), androidx.compose.foundation.shape.e.a), false, null, function0, 7), bVarA, bVarA2, c0814p, 0, 32736);
            c0814p.X(684754450);
            String str2 = userProfileAvatarData.c > 0 ? "" : null;
            c0814p.p(false);
            c0814p.X(-451044724);
            if (str2 != null) {
                F5.b(androidx.compose.ui.platform.N.G(c0418x.a(qVar, androidx.compose.ui.b.c), "unreadDotTestTag"), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), 0L, c0814p, 0);
            }
            androidx.compose.ui.node.B.s(c0814p, false, false, true);
        }
        androidx.compose.ui.q qVar2 = qVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 12, userProfileAvatarData, qVar2, function0);
        }
    }

    public static final int b(int i, List list) {
        int i2 = ((androidx.compose.ui.text.q) CollectionsKt.U(list)).c;
        if (i > ((androidx.compose.ui.text.q) CollectionsKt.U(list)).c) {
            throw new IllegalArgumentException(androidx.compose.animation.d0.p("Index ", i, " should be less or equal than last line's end ", i2).toString());
        }
        int size = list.size() - 1;
        int i3 = 0;
        while (i3 <= size) {
            int i4 = (i3 + size) >>> 1;
            androidx.compose.ui.text.q qVar = (androidx.compose.ui.text.q) list.get(i4);
            char c = qVar.b > i ? (char) 1 : qVar.c <= i ? (char) 65535 : (char) 0;
            if (c < 0) {
                i3 = i4 + 1;
            } else {
                if (c <= 0) {
                    return i4;
                }
                size = i4 - 1;
            }
        }
        return -(i3 + 1);
    }

    public static final int c(int i, ArrayList arrayList) {
        int size = arrayList.size() - 1;
        int i2 = 0;
        while (i2 <= size) {
            int i3 = (i2 + size) >>> 1;
            androidx.compose.ui.text.q qVar = (androidx.compose.ui.text.q) arrayList.get(i3);
            char c = qVar.d > i ? (char) 1 : qVar.e <= i ? (char) 65535 : (char) 0;
            if (c < 0) {
                i2 = i3 + 1;
            } else {
                if (c <= 0) {
                    return i3;
                }
                size = i3 - 1;
            }
        }
        return -(i2 + 1);
    }

    public static final int d(ArrayList arrayList, float f) {
        if (f <= DefinitionKt.NO_Float_VALUE) {
            return 0;
        }
        if (f >= ((androidx.compose.ui.text.q) CollectionsKt.U(arrayList)).g) {
            return kotlin.collections.B.i(arrayList);
        }
        int size = arrayList.size() - 1;
        int i = 0;
        while (i <= size) {
            int i2 = (i + size) >>> 1;
            androidx.compose.ui.text.q qVar = (androidx.compose.ui.text.q) arrayList.get(i2);
            char c = qVar.f > f ? (char) 1 : qVar.g <= f ? (char) 65535 : (char) 0;
            if (c < 0) {
                i = i2 + 1;
            } else {
                if (c <= 0) {
                    return i2;
                }
                size = i2 - 1;
            }
        }
        return -(i + 1);
    }

    public static final void e(ArrayList arrayList, long j, Function1 function1) {
        int size = arrayList.size();
        for (int iB = b(androidx.compose.ui.text.K.e(j), arrayList); iB < size; iB++) {
            androidx.compose.ui.text.q qVar = (androidx.compose.ui.text.q) arrayList.get(iB);
            if (qVar.b >= androidx.compose.ui.text.K.d(j)) {
                return;
            }
            if (qVar.b != qVar.c) {
                function1.invoke(qVar);
            }
        }
    }

    public static com.quizlet.themes.b f(InterfaceC0806l interfaceC0806l) {
        return (com.quizlet.themes.b) ((C0814p) interfaceC0806l).j(com.quizlet.themes.g.a);
    }

    public static com.quizlet.themes.f g(InterfaceC0806l interfaceC0806l) {
        return (com.quizlet.themes.f) ((C0814p) interfaceC0806l).j(com.quizlet.themes.w.a);
    }
}
