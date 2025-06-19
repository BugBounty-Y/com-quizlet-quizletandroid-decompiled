package androidx.recyclerview.widget;

/* loaded from: classes.dex */
public final class I0 extends AbstractC1390s0 {
    public boolean a = false;
    public final /* synthetic */ T b;

    public I0(T t) {
        this.b = t;
    }

    @Override // androidx.recyclerview.widget.AbstractC1390s0
    public final void a(RecyclerView recyclerView, int i) {
        if (i == 0 && this.a) {
            this.a = false;
            this.b.l();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1390s0
    public final void b(RecyclerView recyclerView, int i, int i2) {
        if (i == 0 && i2 == 0) {
            return;
        }
        this.a = true;
    }
}
