package androidx.lifecycle;

/* loaded from: classes.dex */
public final class Q extends S implements H {
    public final J e;
    public final /* synthetic */ T f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q(T t, J j, Z z) {
        super(t, z);
        this.f = t;
        this.e = j;
    }

    @Override // androidx.lifecycle.S
    public final void b() {
        this.e.getLifecycle().b(this);
    }

    @Override // androidx.lifecycle.S
    public final boolean c(J j) {
        return this.e == j;
    }

    @Override // androidx.lifecycle.H
    public final void d(J j, A a) {
        J j2 = this.e;
        B b = ((L) j2.getLifecycle()).d;
        if (b == B.a) {
            this.f.k(this.a);
            return;
        }
        B b2 = null;
        while (b2 != b) {
            a(e());
            b2 = b;
            b = ((L) j2.getLifecycle()).d;
        }
    }

    @Override // androidx.lifecycle.S
    public final boolean e() {
        return ((L) this.e.getLifecycle()).d.a(B.d);
    }
}
