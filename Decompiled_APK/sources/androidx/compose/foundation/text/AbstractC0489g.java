package androidx.compose.foundation.text;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.text.C0985e;
import androidx.compose.ui.text.C0995g;
import java.util.List;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.text.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0489g {
    public static final Pair a;

    static {
        kotlin.collections.K k = kotlin.collections.K.a;
        a = new Pair(k, k);
    }

    public static final void a(C0995g c0995g, List list, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1794596951);
        int i2 = (i & 6) == 0 ? (c0814p.f(c0995g) ? 4 : 2) | i : i;
        if ((i & 48) == 0) {
            i2 |= c0814p.h(list) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            int size = list.size();
            for (int i3 = 0; i3 < size; i3++) {
                C0985e c0985e = (C0985e) list.get(i3);
                kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) c0985e.a;
                C0487f c0487f = C0487f.b;
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                int i4 = c0814p.P;
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
                C0776c.E(c0814p, c0487f, C0914j.f);
                C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
                C0912h c0912h = C0914j.g;
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                    android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
                }
                C0776c.E(c0814p, qVarC, C0914j.d);
                cVar.invoke(c0995g.subSequence(c0985e.b, c0985e.c).a, c0814p, 0);
                c0814p.p(true);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.animation.core.D0(c0995g, list, i, 6);
        }
    }
}
