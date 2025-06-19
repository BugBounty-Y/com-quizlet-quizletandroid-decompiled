package coil3;

import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e implements j {
    public final Drawable a;

    public e(Drawable drawable) {
        this.a = drawable;
    }

    @Override // coil3.j
    public final long a() {
        Drawable drawable = this.a;
        long jB = coil3.util.l.b(drawable) * 4 * coil3.util.l.a(drawable);
        if (jB < 0) {
            return 0L;
        }
        return jB;
    }

    @Override // coil3.j
    public final int b() {
        return coil3.util.l.a(this.a);
    }

    @Override // coil3.j
    public final boolean c() {
        return false;
    }

    @Override // coil3.j
    public final void d(Canvas canvas) {
        this.a.draw(canvas);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof e) {
            return Intrinsics.b(this.a, ((e) obj).a);
        }
        return false;
    }

    @Override // coil3.j
    public final int getWidth() {
        return coil3.util.l.b(this.a);
    }

    public final int hashCode() {
        return Boolean.hashCode(false) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "DrawableImage(drawable=" + this.a + ", shareable=false)";
    }
}
