package androidx.compose.ui;

/* loaded from: classes.dex */
public final class e implements c {
    public final float a;

    public e(float f) {
        this.a = f;
    }

    @Override // androidx.compose.ui.c
    public final int a(int i, int i2, androidx.compose.ui.unit.k kVar) {
        return Math.round((1 + this.a) * ((i2 - i) / 2.0f));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof e) && Float.compare(this.a, ((e) obj).a) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.p(new StringBuilder("Horizontal(bias="), this.a, ')');
    }
}
