package androidx.compose.animation;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c0 {
    public final float a;
    public final androidx.compose.animation.core.D b;

    public c0(float f, androidx.compose.animation.core.D d) {
        this.a = f;
        this.b = d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c0)) {
            return false;
        }
        c0 c0Var = (c0) obj;
        return Float.compare(this.a, c0Var.a) == 0 && Intrinsics.b(this.b, c0Var.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Float.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "Fade(alpha=" + this.a + ", animationSpec=" + this.b + ')';
    }
}
