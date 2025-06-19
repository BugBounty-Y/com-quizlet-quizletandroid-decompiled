package androidx.fragment.app;

/* loaded from: classes.dex */
public final class X extends N {
    public final /* synthetic */ AbstractC1136h0 b;

    public X(AbstractC1136h0 abstractC1136h0) {
        this.b = abstractC1136h0;
    }

    @Override // androidx.fragment.app.N
    public final Fragment a(String str) {
        return Fragment.instantiate(this.b.x.b, str, null);
    }
}
