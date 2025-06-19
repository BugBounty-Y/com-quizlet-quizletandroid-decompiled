package androidx.compose.ui.graphics;

import android.graphics.ColorFilter;
import androidx.compose.animation.d0;

/* renamed from: androidx.compose.ui.graphics.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0853m extends AbstractC0874w {
    public final long b;
    public final int c;

    public C0853m(long j, int i, ColorFilter colorFilter) {
        super(colorFilter);
        this.b = j;
        this.c = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0853m)) {
            return false;
        }
        C0853m c0853m = (C0853m) obj;
        if (C0861v.c(this.b, c0853m.b)) {
            return this.c == c0853m.c;
        }
        return false;
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Integer.hashCode(this.c) + (Long.hashCode(this.b) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BlendModeColorFilter(color=");
        d0.x(this.b, ", blendMode=", sb);
        int i = this.c;
        sb.append((Object) (i == 0 ? "Clear" : i == 1 ? "Src" : i == 2 ? "Dst" : i == 3 ? "SrcOver" : i == 4 ? "DstOver" : i == 5 ? "SrcIn" : i == 6 ? "DstIn" : i == 7 ? "SrcOut" : i == 8 ? "DstOut" : i == 9 ? "SrcAtop" : i == 10 ? "DstAtop" : i == 11 ? "Xor" : i == 12 ? "Plus" : i == 13 ? "Modulate" : i == 14 ? "Screen" : i == 15 ? "Overlay" : i == 16 ? "Darken" : i == 17 ? "Lighten" : i == 18 ? "ColorDodge" : i == 19 ? "ColorBurn" : i == 20 ? "HardLight" : i == 21 ? "Softlight" : i == 22 ? "Difference" : i == 23 ? "Exclusion" : i == 24 ? "Multiply" : i == 25 ? "Hue" : i == 26 ? "Saturation" : i == 27 ? "Color" : i == 28 ? "Luminosity" : "Unknown"));
        sb.append(')');
        return sb.toString();
    }
}
