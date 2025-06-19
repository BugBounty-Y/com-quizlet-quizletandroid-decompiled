package androidx.compose.ui.text;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.text.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0983c {
    public final Object a;
    public final int b;
    public int c;
    public final String d;

    public C0983c(int i, int i2, Object obj, String str) {
        this.a = obj;
        this.b = i;
        this.c = i2;
        this.d = str;
    }

    public final C0985e a(int i) {
        int i2 = this.c;
        if (i2 != Integer.MIN_VALUE) {
            i = i2;
        }
        if (i == Integer.MIN_VALUE) {
            throw new IllegalStateException("Item.end should be set first");
        }
        return new C0985e(this.b, i, this.a, this.d);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0983c)) {
            return false;
        }
        C0983c c0983c = (C0983c) obj;
        return Intrinsics.b(this.a, c0983c.a) && this.b == c0983c.b && this.c == c0983c.c && Intrinsics.b(this.d, c0983c.d);
    }

    public final int hashCode() {
        Object obj = this.a;
        return this.d.hashCode() + d0.b(this.c, d0.b(this.b, (obj == null ? 0 : obj.hashCode()) * 31, 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MutableRange(item=");
        sb.append(this.a);
        sb.append(", start=");
        sb.append(this.b);
        sb.append(", end=");
        sb.append(this.c);
        sb.append(", tag=");
        return d0.r(sb, this.d, ')');
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public /* synthetic */ C0983c(Object obj, int i, int i2, int i3) {
        String str;
        i2 = (i3 & 4) != 0 ? Integer.MIN_VALUE : i2;
        if ((i3 & 8) != 0) {
            str = "";
        } else {
            str = "androidx.compose.foundation.text.inlineContent";
        }
        this(i, i2, obj, str);
    }
}
