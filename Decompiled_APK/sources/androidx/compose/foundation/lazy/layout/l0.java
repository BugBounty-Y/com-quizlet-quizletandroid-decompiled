package androidx.compose.foundation.lazy.layout;

import androidx.compose.animation.C0278e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.X0;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class l0 implements androidx.compose.runtime.saveable.i, androidx.compose.runtime.saveable.c {
    public final androidx.compose.runtime.saveable.j a;
    public final InterfaceC0773a0 b;
    public final LinkedHashSet c;

    public l0(androidx.compose.runtime.saveable.i iVar, Map map) {
        j0 j0Var = new j0(iVar, 0);
        X0 x0 = androidx.compose.runtime.saveable.k.a;
        this.a = new androidx.compose.runtime.saveable.j(map, j0Var);
        this.b = C0776c.z(null);
        this.c = new LinkedHashSet();
    }

    @Override // androidx.compose.runtime.saveable.i
    public final boolean a(Object obj) {
        return this.a.a(obj);
    }

    @Override // androidx.compose.runtime.saveable.i
    public final Map b() {
        androidx.compose.runtime.saveable.c cVar = (androidx.compose.runtime.saveable.c) ((L0) this.b).getValue();
        if (cVar != null) {
            Iterator it2 = this.c.iterator();
            while (it2.hasNext()) {
                cVar.f(it2.next());
            }
        }
        return this.a.b();
    }

    @Override // androidx.compose.runtime.saveable.i
    public final Object c(String str) {
        return this.a.c(str);
    }

    @Override // androidx.compose.runtime.saveable.i
    public final androidx.compose.runtime.saveable.h d(String str, Function0 function0) {
        return this.a.d(str, function0);
    }

    @Override // androidx.compose.runtime.saveable.c
    public final void e(Object obj, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-697180401);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(obj) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(dVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(this) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.saveable.c cVar = (androidx.compose.runtime.saveable.c) ((L0) this.b).getValue();
            if (cVar == null) {
                throw new IllegalArgumentException("null wrappedHolder");
            }
            cVar.e(obj, dVar, c0814p, i2 & 126);
            boolean zH = c0814p.h(this) | c0814p.h(obj);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new C0278e(17, this, obj);
                c0814p.i0(objI);
            }
            C0776c.d(obj, (Function1) objI, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.a(i, 2, this, obj, dVar);
        }
    }

    @Override // androidx.compose.runtime.saveable.c
    public final void f(Object obj) {
        androidx.compose.runtime.saveable.c cVar = (androidx.compose.runtime.saveable.c) ((L0) this.b).getValue();
        if (cVar == null) {
            throw new IllegalArgumentException("null wrappedHolder");
        }
        cVar.f(obj);
    }
}
