package androidx.glance;

/* loaded from: classes.dex */
public final class l implements k {
    public a b;
    public s c;
    public p a = n.a;
    public int d = 1;

    @Override // androidx.glance.k
    public final p a() {
        return this.a;
    }

    @Override // androidx.glance.k
    public final void b(p pVar) {
        this.a = pVar;
    }

    @Override // androidx.glance.k
    public final k copy() {
        l lVar = new l();
        lVar.a = this.a;
        lVar.b = this.b;
        lVar.c = this.c;
        lVar.d = this.d;
        return lVar;
    }

    public final String toString() {
        return "EmittableImage(modifier=" + this.a + ", provider=" + this.b + ", colorFilterParams=" + this.c + ", contentScale=" + ((Object) androidx.glance.layout.h.a(this.d)) + ')';
    }
}
