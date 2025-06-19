package androidx.compose.ui.text.style;

import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.C0861v;
import kotlin.C;
import kotlin.D;

/* loaded from: classes.dex */
public final class c implements n {
    public final long a;

    public c(long j) {
        this.a = j;
        if (j == 16) {
            throw new IllegalArgumentException("ColorStyle value must be specified, use TextForegroundStyle.Unspecified instead.");
        }
    }

    @Override // androidx.compose.ui.text.style.n
    public final float a() {
        return C0861v.d(this.a);
    }

    @Override // androidx.compose.ui.text.style.n
    public final long b() {
        return this.a;
    }

    @Override // androidx.compose.ui.text.style.n
    public final AbstractC0857q c() {
        return null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && C0861v.c(this.a, ((c) obj).a);
    }

    public final int hashCode() {
        int i = C0861v.h;
        C c = D.b;
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return "ColorStyle(value=" + ((Object) C0861v.i(this.a)) + ')';
    }
}
