package androidx.compose.foundation.lazy.grid;

import androidx.appcompat.widget.C0122z;
import androidx.compose.animation.core.D0;
import androidx.compose.foundation.layout.C0404p;
import androidx.compose.foundation.lazy.layout.AbstractC0448u;
import androidx.compose.foundation.lazy.layout.N;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j implements N {
    public final A a;
    public final i b;
    public final C0122z c;

    public j(A a, i iVar, C0122z c0122z) {
        this.a = a;
        this.b = iVar;
        this.c = c0122z;
    }

    @Override // androidx.compose.foundation.lazy.layout.N
    public final int a(Object obj) {
        return this.c.a(obj);
    }

    @Override // androidx.compose.foundation.lazy.layout.N
    public final Object b(int i) {
        Object objP = this.c.p(i);
        return objP == null ? this.b.k(i) : objP;
    }

    @Override // androidx.compose.foundation.lazy.layout.N
    public final Object c(int i) {
        return this.b.i(i);
    }

    @Override // androidx.compose.foundation.lazy.layout.N
    public final int d() {
        return this.b.j().b;
    }

    @Override // androidx.compose.foundation.lazy.layout.N
    public final void e(int i, Object obj, InterfaceC0806l interfaceC0806l, int i2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1493551140);
        int i3 = (c0814p.d(i) ? 4 : 2) | i2 | (c0814p.h(obj) ? 32 : 16) | (c0814p.f(this) ? 256 : 128);
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC0448u.b(obj, i, this.a.o, androidx.compose.runtime.internal.e.e(726189336, new C0404p(this, i, 2), c0814p), c0814p, ((i3 >> 3) & 14) | 3072 | ((i3 << 3) & ContentType.LONG_FORM_ON_DEMAND));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new D0(this, i, obj, i2, 3);
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        return Intrinsics.b(this.b, ((j) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }
}
