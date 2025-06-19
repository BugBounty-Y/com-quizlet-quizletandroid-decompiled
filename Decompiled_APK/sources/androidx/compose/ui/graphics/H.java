package androidx.compose.ui.graphics;

/* loaded from: classes.dex */
public final class H {
    public final int a;

    public final boolean equals(Object obj) {
        if (obj instanceof H) {
            return this.a == ((H) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        int i = this.a;
        return i == 0 ? "Argb8888" : i == 1 ? "Alpha8" : i == 2 ? "Rgb565" : i == 3 ? "F16" : i == 4 ? "Gpu" : "Unknown";
    }
}
