package androidx.glance.layout;

/* loaded from: classes.dex */
public final class l implements androidx.glance.k {
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
        l lVar = new l();
        lVar.a = this.a;
        return lVar;
    }

    public final String toString() {
        return "EmittableSpacer(modifier=" + this.a + ')';
    }
}
