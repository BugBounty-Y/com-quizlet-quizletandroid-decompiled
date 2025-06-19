package androidx.collection;

/* loaded from: classes.dex */
public final class X extends kotlin.collections.P {
    public int a;
    public final /* synthetic */ W b;

    public X(W w) {
        this.b = w;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.a < this.b.g();
    }

    @Override // kotlin.collections.P
    public final int nextInt() {
        int i = this.a;
        this.a = i + 1;
        return this.b.e(i);
    }
}
