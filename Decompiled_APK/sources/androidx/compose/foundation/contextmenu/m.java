package androidx.compose.foundation.contextmenu;

import com.google.android.gms.internal.mlkit_vision_barcode.Q4;

/* loaded from: classes.dex */
public final class m extends n {
    public final long a;

    public m(long j) {
        this.a = j;
        if (!Q4.h(j)) {
            throw new IllegalStateException("ContextMenuState.Status should never be open with an unspecified offset. Use ContextMenuState.Status.Closed instead.");
        }
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        return androidx.compose.ui.geometry.b.b(this.a, ((m) obj).a);
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return "Open(offset=" + ((Object) androidx.compose.ui.geometry.b.j(this.a)) + ')';
    }
}
