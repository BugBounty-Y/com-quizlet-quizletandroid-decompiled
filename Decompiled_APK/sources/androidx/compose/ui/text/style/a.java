package androidx.compose.ui.text.style;

/* loaded from: classes.dex */
public final class a {
    public final float a;

    public final boolean equals(Object obj) {
        if (obj instanceof a) {
            return Float.compare(this.a, ((a) obj).a) == 0;
        }
        return false;
    }

    public final int hashCode() {
        return Float.hashCode(this.a);
    }

    public final String toString() {
        return "BaselineShift(multiplier=" + this.a + ')';
    }
}
