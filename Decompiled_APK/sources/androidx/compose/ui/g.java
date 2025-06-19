package androidx.compose.ui;

/* loaded from: classes.dex */
public final class g implements c {
    public final float a;

    public g(float f) {
        this.a = f;
    }

    @Override // androidx.compose.ui.c
    public final int a(int i, int i2, androidx.compose.ui.unit.k kVar) {
        float f = (i2 - i) / 2.0f;
        androidx.compose.ui.unit.k kVar2 = androidx.compose.ui.unit.k.a;
        float f2 = this.a;
        if (kVar != kVar2) {
            f2 *= -1;
        }
        return Math.round((1 + f2) * f);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && Float.compare(this.a, ((g) obj).a) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.p(new StringBuilder("Horizontal(bias="), this.a, ')');
    }
}
