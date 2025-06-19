package androidx.compose.ui.layout;

/* renamed from: androidx.compose.ui.layout.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0891l implements InterfaceC0889j {
    @Override // androidx.compose.ui.layout.InterfaceC0889j
    public final long a(long j, long j2) {
        return AbstractC0897s.b(1.0f, 1.0f);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0891l)) {
            return false;
        }
        ((C0891l) obj).getClass();
        return Float.compare(1.0f, 1.0f) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(1.0f);
    }

    public final String toString() {
        return "FixedScale(value=1.0)";
    }
}
