package androidx.compose.ui.unit;

/* loaded from: classes.dex */
public final class l implements androidx.compose.ui.unit.fontscaling.a {
    public final float a;

    public l(float f) {
        this.a = f;
    }

    @Override // androidx.compose.ui.unit.fontscaling.a
    public final float a(float f) {
        return f / this.a;
    }

    @Override // androidx.compose.ui.unit.fontscaling.a
    public final float b(float f) {
        return f * this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof l) && Float.compare(this.a, ((l) obj).a) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.p(new StringBuilder("LinearFontScaleConverter(fontScale="), this.a, ')');
    }
}
