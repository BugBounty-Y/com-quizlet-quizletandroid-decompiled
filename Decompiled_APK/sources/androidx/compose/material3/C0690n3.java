package androidx.compose.material3;

import androidx.compose.ui.graphics.C0861v;

/* renamed from: androidx.compose.material3.n3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0690n3 {
    public final long a = C0861v.g;

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C0690n3) {
            return C0861v.c(this.a, ((C0690n3) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.a) * 31;
    }

    public final String toString() {
        return "RippleConfiguration(color=" + ((Object) C0861v.i(this.a)) + ", rippleAlpha=null)";
    }
}
