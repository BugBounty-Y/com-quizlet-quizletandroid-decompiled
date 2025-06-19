package androidx.compose.ui.graphics;

import android.graphics.ColorFilter;
import android.graphics.ColorMatrixColorFilter;
import java.util.Arrays;

/* renamed from: androidx.compose.ui.graphics.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0875x extends AbstractC0874w {
    public float[] b;

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0875x)) {
            return false;
        }
        float[] fArrA = this.b;
        C0876y c0876y = C0876y.a;
        if (fArrA == null) {
            ColorFilter colorFilter = this.a;
            if (!(colorFilter instanceof ColorMatrixColorFilter)) {
                throw new IllegalArgumentException("Unable to obtain ColorMatrix from Android ColorMatrixColorFilter. This method was invoked on an unsupported Android version");
            }
            fArrA = c0876y.a((ColorMatrixColorFilter) colorFilter);
            this.b = fArrA;
        }
        C0875x c0875x = (C0875x) obj;
        float[] fArrA2 = c0875x.b;
        if (fArrA2 == null) {
            ColorFilter colorFilter2 = c0875x.a;
            if (!(colorFilter2 instanceof ColorMatrixColorFilter)) {
                throw new IllegalArgumentException("Unable to obtain ColorMatrix from Android ColorMatrixColorFilter. This method was invoked on an unsupported Android version");
            }
            fArrA2 = c0876y.a((ColorMatrixColorFilter) colorFilter2);
            c0875x.b = fArrA2;
        }
        return Arrays.equals(fArrA, fArrA2);
    }

    public final int hashCode() {
        float[] fArr = this.b;
        if (fArr != null) {
            return Arrays.hashCode(fArr);
        }
        return 0;
    }

    public final String toString() {
        String str;
        StringBuilder sb = new StringBuilder("ColorMatrixColorFilter(colorMatrix=");
        float[] fArr = this.b;
        if (fArr == null) {
            str = "null";
        } else {
            str = "ColorMatrix(values=" + Arrays.toString(fArr) + ')';
        }
        sb.append((Object) str);
        sb.append(')');
        return sb.toString();
    }
}
