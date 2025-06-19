package kotlin.collections;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* renamed from: kotlin.collections.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4913d {
    public C4913d(DefaultConstructorMarker defaultConstructorMarker) {
    }

    public static void a(int i, int i2, int i3) {
        if (i < 0 || i2 > i3) {
            StringBuilder sbW = android.support.v4.media.session.a.w("startIndex: ", i, ", endIndex: ", ", size: ", i2);
            sbW.append(i3);
            throw new IndexOutOfBoundsException(sbW.toString());
        }
        if (i > i2) {
            throw new IllegalArgumentException(androidx.compose.animation.d0.p("startIndex: ", i, " > endIndex: ", i2));
        }
    }

    public static void b(int i, int i2) {
        if (i < 0 || i >= i2) {
            throw new IndexOutOfBoundsException(androidx.compose.animation.d0.p("index: ", i, ", size: ", i2));
        }
    }

    public static void c(int i, int i2) {
        if (i < 0 || i > i2) {
            throw new IndexOutOfBoundsException(androidx.compose.animation.d0.p("index: ", i, ", size: ", i2));
        }
    }

    public static void d(int i, int i2, int i3) {
        if (i < 0 || i2 > i3) {
            StringBuilder sbW = android.support.v4.media.session.a.w("fromIndex: ", i, ", toIndex: ", ", size: ", i2);
            sbW.append(i3);
            throw new IndexOutOfBoundsException(sbW.toString());
        }
        if (i > i2) {
            throw new IllegalArgumentException(androidx.compose.animation.d0.p("fromIndex: ", i, " > toIndex: ", i2));
        }
    }

    public static int e(int i, int i2) {
        int i3 = i + (i >> 1);
        if (i3 - i2 < 0) {
            i3 = i2;
        }
        if (i3 - 2147483639 <= 0) {
            return i3;
        }
        if (i2 > 2147483639) {
            return SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        return 2147483639;
    }
}
