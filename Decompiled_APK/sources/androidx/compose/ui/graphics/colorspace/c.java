package androidx.compose.ui.graphics.colorspace;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class c {
    public final String a;
    public final long b;
    public final int c;

    public c(int i, long j, String str) {
        this.a = str;
        this.b = j;
        this.c = i;
        if (str.length() == 0) {
            throw new IllegalArgumentException("The name of a color space cannot be null and must contain at least 1 character");
        }
        if (i < -1 || i > 63) {
            throw new IllegalArgumentException("The id must be between -1 and 63");
        }
    }

    public abstract float a(int i);

    public abstract float b(int i);

    public boolean c() {
        return false;
    }

    public abstract long d(float f, float f2, float f3);

    public abstract float e(float f, float f2, float f3);

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        c cVar = (c) obj;
        if (this.c == cVar.c && Intrinsics.b(this.a, cVar.a)) {
            return b.a(this.b, cVar.b);
        }
        return false;
    }

    public abstract long f(float f, float f2, float f3, float f4, c cVar);

    public int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        int i = b.e;
        return d0.d(iHashCode, 31, this.b) + this.c;
    }

    public final String toString() {
        return this.a + " (id=" + this.c + ", model=" + ((Object) b.b(this.b)) + ')';
    }
}
