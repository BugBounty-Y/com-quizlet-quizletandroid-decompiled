package androidx.recyclerview.widget;

/* loaded from: classes.dex */
public final class X {
    public final R0 a;
    public final J0 b;
    public final AbstractC1361d0 c;
    public final C1372j d;
    public int e;
    public final W f;

    public X(AbstractC1361d0 abstractC1361d0, C1372j c1372j, S0 s0, J0 j0) {
        W w = new W(this, 0);
        this.f = w;
        this.c = abstractC1361d0;
        this.d = c1372j;
        this.a = s0.b(this);
        this.b = j0;
        this.e = abstractC1361d0.getItemCount();
        abstractC1361d0.registerAdapterDataObserver(w);
    }
}
