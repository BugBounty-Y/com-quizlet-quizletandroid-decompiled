package androidx.glance.appwidget;

/* loaded from: classes.dex */
public final class C implements androidx.glance.k {
    public androidx.glance.p a = androidx.glance.n.a;

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
        C c = new C();
        c.a = this.a;
        return c;
    }
}
