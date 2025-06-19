package androidx.compose.foundation.layout;

/* loaded from: classes.dex */
public final class K extends AbstractC0382e {
    public final C0376b h;

    public K(C0376b c0376b) {
        this.h = c0376b;
    }

    @Override // androidx.compose.foundation.layout.AbstractC0382e
    public final int g(int i, androidx.compose.ui.unit.k kVar, androidx.compose.ui.layout.W w, int i2) {
        int iD0 = w.d0(this.h.a);
        if (iD0 == Integer.MIN_VALUE) {
            return 0;
        }
        int i3 = i2 - iD0;
        return kVar == androidx.compose.ui.unit.k.b ? i - i3 : i3;
    }

    @Override // androidx.compose.foundation.layout.AbstractC0382e
    public final Integer i(androidx.compose.ui.layout.W w) {
        return Integer.valueOf(w.d0(this.h.a));
    }
}
