package androidx.compose.foundation.contextmenu;

import androidx.compose.foundation.C0557z;
import androidx.compose.foundation.text.C0547v;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class j {
    public final androidx.compose.runtime.snapshots.q a = new androidx.compose.runtime.snapshots.q();

    public static void b(j jVar, C0547v c0547v, boolean z, Function0 function0) {
        jVar.getClass();
        jVar.a.add(new androidx.compose.runtime.internal.d(true, 262103052, new C0557z(c0547v, z, function0)));
    }

    public final void a(c cVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1320309496);
        int i2 = (c0814p.f(cVar) ? 4 : 2) | i | (c0814p.f(this) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.snapshots.q qVar = this.a;
            int size = qVar.size();
            for (int i3 = 0; i3 < size; i3++) {
                ((kotlin.jvm.functions.c) qVar.get(i3)).invoke(cVar, c0814p, Integer.valueOf(i2 & 14));
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new i(this, cVar, i, 0);
        }
    }
}
