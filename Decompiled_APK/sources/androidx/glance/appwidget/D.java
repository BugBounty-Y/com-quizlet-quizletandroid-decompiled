package androidx.glance.appwidget;

/* loaded from: classes.dex */
public final class D implements androidx.glance.k {
    public float b;
    public androidx.glance.p a = androidx.glance.n.a;
    public androidx.glance.unit.a c = y0.a;
    public androidx.glance.unit.a d = y0.b;

    @Override // androidx.glance.k
    public final androidx.glance.p a() {
        return this.a;
    }

    @Override // androidx.glance.k
    public final void b(androidx.glance.p pVar) {
        this.a = pVar;
    }

    @Override // androidx.glance.k
    public final androidx.glance.k copy() {
        D d = new D();
        d.a = this.a;
        d.b = this.b;
        d.c = this.c;
        d.d = this.d;
        return d;
    }

    public final String toString() {
        return "EmittableLinearProgressIndicator(modifier=" + this.a + ", progress=" + this.b + ", indeterminate=false, color=" + this.c + ", backgroundColor=" + this.d + ')';
    }
}
