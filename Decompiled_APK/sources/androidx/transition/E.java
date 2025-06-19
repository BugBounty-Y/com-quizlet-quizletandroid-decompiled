package androidx.transition;

/* loaded from: classes.dex */
public final class E extends z {
    public final /* synthetic */ int a = 1;
    public F b;

    public /* synthetic */ E() {
    }

    @Override // androidx.transition.z, androidx.transition.InterfaceC1419w
    public void b(y yVar) {
        switch (this.a) {
            case 1:
                F f = this.b;
                if (!f.I) {
                    f.O();
                    f.I = true;
                    break;
                }
                break;
        }
    }

    @Override // androidx.transition.z, androidx.transition.InterfaceC1419w
    public void d(y yVar) {
        switch (this.a) {
            case 1:
                F f = this.b;
                int i = f.H - 1;
                f.H = i;
                if (i == 0) {
                    f.I = false;
                    f.o();
                }
                yVar.D(this);
                break;
        }
    }

    @Override // androidx.transition.z, androidx.transition.InterfaceC1419w
    public void f(y yVar) {
        switch (this.a) {
            case 0:
                F f = this.b;
                f.F.remove(yVar);
                if (!f.u()) {
                    f.z(f, x.I0, false);
                    f.r = true;
                    f.z(f, x.H0, false);
                    break;
                }
                break;
        }
    }

    public E(F f) {
        this.b = f;
    }
}
