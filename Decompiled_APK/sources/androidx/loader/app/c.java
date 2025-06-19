package androidx.loader.app;

import androidx.compose.ui.node.B;
import androidx.lifecycle.Y;
import androidx.lifecycle.Z;

/* loaded from: classes.dex */
public final class c extends Y {
    public final int l;
    public final androidx.loader.content.c m;
    public Object n;
    public d o;

    public c(int i, androidx.loader.content.c cVar) {
        this.l = i;
        this.m = cVar;
        if (cVar.b != null) {
            throw new IllegalStateException("There is already a listener registered");
        }
        cVar.b = this;
        cVar.a = i;
    }

    @Override // androidx.lifecycle.T
    public final void h() {
        androidx.loader.content.c cVar = this.m;
        cVar.d = true;
        cVar.f = false;
        cVar.e = false;
        cVar.d();
    }

    @Override // androidx.lifecycle.T
    public final void i() {
        androidx.loader.content.c cVar = this.m;
        cVar.d = false;
        cVar.e();
    }

    @Override // androidx.lifecycle.T
    public final void k(Z z) {
        super.k(z);
        this.n = null;
        this.o = null;
    }

    public final void m() {
        androidx.loader.content.c cVar = this.m;
        cVar.c();
        cVar.e = true;
        d dVar = this.o;
        if (dVar != null) {
            k(dVar);
            if (dVar.b) {
                dVar.a.g();
            }
        }
        c cVar2 = cVar.b;
        if (cVar2 == null) {
            throw new IllegalStateException("No listener register");
        }
        if (cVar2 != this) {
            throw new IllegalArgumentException("Attempting to unregister the wrong listener");
        }
        cVar.b = null;
        if (dVar != null) {
            boolean z = dVar.b;
        }
        cVar.f = true;
        cVar.d = false;
        cVar.e = false;
        cVar.g = false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v0, types: [androidx.lifecycle.J, java.lang.Object] */
    public final void n() {
        ?? r0 = this.n;
        d dVar = this.o;
        if (r0 == 0 || dVar == null) {
            return;
        }
        super.k(dVar);
        f(r0, dVar);
    }

    public final String toString() {
        StringBuilder sbL = B.l(64, "LoaderInfo{");
        sbL.append(Integer.toHexString(System.identityHashCode(this)));
        sbL.append(" #");
        sbL.append(this.l);
        sbL.append(" : ");
        Class<?> cls = this.m.getClass();
        sbL.append(cls.getSimpleName());
        sbL.append("{");
        sbL.append(Integer.toHexString(System.identityHashCode(cls)));
        sbL.append("}}");
        return sbL.toString();
    }
}
