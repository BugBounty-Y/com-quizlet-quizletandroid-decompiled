package androidx.compose.foundation.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0409s {
    public static final HashMap a = c(true);
    public static final HashMap b = c(false);
    public static final r c = r.b;

    public static final void a(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-211209833);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i3 = c0814p.P;
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, c, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0404p(qVar, i, 0);
        }
    }

    public static final void b(androidx.compose.ui.layout.V v, androidx.compose.ui.layout.W w, androidx.compose.ui.layout.J j, androidx.compose.ui.unit.k kVar, int i, int i2, androidx.compose.ui.d dVar) {
        androidx.compose.ui.i iVar;
        Object objG = j.G();
        C0402o c0402o = objG instanceof C0402o ? (C0402o) objG : null;
        androidx.compose.ui.layout.V.e(v, w, ((c0402o == null || (iVar = c0402o.n) == null) ? dVar : iVar).a(R5.a(w.a, w.b), R5.a(i, i2), kVar));
    }

    public static final HashMap c(boolean z) {
        HashMap map = new HashMap(9);
        d(map, z, androidx.compose.ui.b.a);
        d(map, z, androidx.compose.ui.b.b);
        d(map, z, androidx.compose.ui.b.c);
        d(map, z, androidx.compose.ui.b.d);
        d(map, z, androidx.compose.ui.b.e);
        d(map, z, androidx.compose.ui.b.f);
        d(map, z, androidx.compose.ui.b.g);
        d(map, z, androidx.compose.ui.b.h);
        d(map, z, androidx.compose.ui.b.i);
        return map;
    }

    public static final void d(HashMap map, boolean z, androidx.compose.ui.i iVar) {
        map.put(iVar, new C0415v(iVar, z));
    }

    public static final androidx.compose.ui.layout.K e(androidx.compose.ui.d dVar, boolean z) {
        androidx.compose.ui.layout.K k = (androidx.compose.ui.layout.K) (z ? a : b).get(dVar);
        return k == null ? new C0415v(dVar, z) : k;
    }
}
