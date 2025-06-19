package androidx.compose.foundation.lazy.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.H0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;

/* loaded from: classes.dex */
public final class Y {
    public final Object a;
    public final Z b;
    public final H0 c = C0776c.w(-1);
    public final H0 d = C0776c.w(0);
    public final InterfaceC0773a0 e = C0776c.z(null);
    public final InterfaceC0773a0 f = C0776c.z(null);

    public Y(Object obj, Z z) {
        this.a = obj;
        this.b = z;
    }

    public final int a() {
        return this.d.i();
    }

    public final Y b() {
        if (a() == 0) {
            this.b.a.add(this);
            Y y = (Y) ((L0) this.f).getValue();
            if (y != null) {
                y.b();
            } else {
                y = null;
            }
            ((L0) this.e).setValue(y);
        }
        this.d.j(a() + 1);
        return this;
    }

    public final void c() {
        if (a() <= 0) {
            throw new IllegalStateException("Release should only be called once");
        }
        this.d.j(a() - 1);
        if (a() == 0) {
            this.b.a.remove(this);
            InterfaceC0773a0 interfaceC0773a0 = this.e;
            Y y = (Y) ((L0) interfaceC0773a0).getValue();
            if (y != null) {
                y.c();
            }
            ((L0) interfaceC0773a0).setValue(null);
        }
    }
}
