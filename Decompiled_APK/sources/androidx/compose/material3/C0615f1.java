package androidx.compose.material3;

/* renamed from: androidx.compose.material3.f1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0615f1 {
    public final int a;

    public final boolean equals(Object obj) {
        if (obj instanceof C0615f1) {
            return this.a == ((C0615f1) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        int i = this.a;
        return i == 0 ? "Picker" : i == 1 ? "Input" : "Unknown";
    }
}
