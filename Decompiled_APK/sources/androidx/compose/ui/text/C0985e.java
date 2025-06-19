package androidx.compose.ui.text;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.text.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0985e {
    public final Object a;
    public final int b;
    public final int c;
    public final String d;

    public C0985e(int i, int i2, Object obj, String str) {
        this.a = obj;
        this.b = i;
        this.c = i2;
        this.d = str;
        if (i > i2) {
            throw new IllegalArgumentException("Reversed range is not supported");
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0985e)) {
            return false;
        }
        C0985e c0985e = (C0985e) obj;
        return Intrinsics.b(this.a, c0985e.a) && this.b == c0985e.b && this.c == c0985e.c && Intrinsics.b(this.d, c0985e.d);
    }

    public final int hashCode() {
        Object obj = this.a;
        return this.d.hashCode() + d0.b(this.c, d0.b(this.b, (obj == null ? 0 : obj.hashCode()) * 31, 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Range(item=");
        sb.append(this.a);
        sb.append(", start=");
        sb.append(this.b);
        sb.append(", end=");
        sb.append(this.c);
        sb.append(", tag=");
        return d0.r(sb, this.d, ')');
    }

    public C0985e(Object obj, int i, int i2) {
        this(i, i2, obj, "");
    }
}
