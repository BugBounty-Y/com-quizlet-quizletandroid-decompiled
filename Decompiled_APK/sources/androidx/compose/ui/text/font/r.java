package androidx.compose.ui.text.font;

/* loaded from: classes.dex */
public final class r {
    public final int a;

    public final boolean equals(Object obj) {
        if (obj instanceof r) {
            return this.a == ((r) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        int i = this.a;
        return i == 0 ? "None" : i == 1 ? "All" : i == 2 ? "Weight" : i == 3 ? "Style" : "Invalid";
    }
}
