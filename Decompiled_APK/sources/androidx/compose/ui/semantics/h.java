package androidx.compose.ui.semantics;

/* loaded from: classes.dex */
public final class h {
    public final int a;

    public final boolean equals(Object obj) {
        if (obj instanceof h) {
            return this.a == ((h) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        int i = this.a;
        return i == 0 ? "Button" : i == 1 ? "Checkbox" : i == 2 ? "Switch" : i == 3 ? "RadioButton" : i == 4 ? "Tab" : i == 5 ? "Image" : i == 6 ? "DropdownList" : "Unknown";
    }
}
