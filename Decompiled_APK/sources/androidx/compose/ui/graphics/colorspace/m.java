package androidx.compose.ui.graphics.colorspace;

/* loaded from: classes.dex */
public final /* synthetic */ class m implements i {
    public final /* synthetic */ int a;
    public final /* synthetic */ q b;

    public /* synthetic */ m(q qVar, int i) {
        this.a = i;
        this.b = qVar;
    }

    @Override // androidx.compose.ui.graphics.colorspace.i
    public final double d(double d) {
        switch (this.a) {
            case 0:
                return kotlin.ranges.l.a(this.b.k.d(d), r10.e, r10.f);
            default:
                return this.b.n.d(kotlin.ranges.l.a(d, r0.e, r0.f));
        }
    }
}
