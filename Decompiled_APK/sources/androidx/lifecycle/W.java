package androidx.lifecycle;

/* loaded from: classes.dex */
public final class W implements Z {
    public final T a;
    public final Z b;
    public int c = -1;

    public W(T t, Z z) {
        this.a = t;
        this.b = z;
    }

    @Override // androidx.lifecycle.Z
    public final void a(Object obj) {
        int i = this.c;
        int i2 = this.a.g;
        if (i != i2) {
            this.c = i2;
            this.b.a(obj);
        }
    }

    public final void b() {
        this.a.g(this);
    }
}
