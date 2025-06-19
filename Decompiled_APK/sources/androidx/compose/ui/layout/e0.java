package androidx.compose.ui.layout;

/* loaded from: classes.dex */
public final class e0 {
    public final h0 a;
    public G b;
    public final d0 c = new d0(this, 2);
    public final d0 d = new d0(this, 0);
    public final d0 e = new d0(this, 1);

    public e0(h0 h0Var) {
        this.a = h0Var;
    }

    public final G a() {
        G g = this.b;
        if (g != null) {
            return g;
        }
        throw new IllegalArgumentException("SubcomposeLayoutState is not attached to SubcomposeLayout");
    }
}
