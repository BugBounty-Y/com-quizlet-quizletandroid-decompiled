package retrofit2;

/* loaded from: classes3.dex */
public final class C extends S {
    public final boolean d;

    public C(boolean z) {
        this.d = z;
    }

    @Override // retrofit2.S
    public final void a(H h, Object obj) {
        if (obj == null) {
            return;
        }
        h.d(obj.toString(), null, this.d);
    }
}
