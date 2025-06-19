package androidx.compose.ui.unit;

/* loaded from: classes.dex */
public final class c implements b {
    public final float a;
    public final float b;

    public c(float f, float f2) {
        this.a = f;
        this.b = f2;
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.b;
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Float.compare(this.a, cVar.a) == 0 && Float.compare(this.b, cVar.b) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.b) + (Float.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DensityImpl(density=");
        sb.append(this.a);
        sb.append(", fontScale=");
        return android.support.v4.media.session.a.p(sb, this.b, ')');
    }
}
