package androidx.compose.ui.text.style;

import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.T;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements n {
    public final T a;
    public final float b;

    public b(T t, float f) {
        this.a = t;
        this.b = f;
    }

    @Override // androidx.compose.ui.text.style.n
    public final float a() {
        return this.b;
    }

    @Override // androidx.compose.ui.text.style.n
    public final long b() {
        int i = C0861v.h;
        return C0861v.g;
    }

    @Override // androidx.compose.ui.text.style.n
    public final AbstractC0857q c() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Float.compare(this.b, bVar.b) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BrushStyle(value=");
        sb.append(this.a);
        sb.append(", alpha=");
        return android.support.v4.media.session.a.p(sb, this.b, ')');
    }
}
