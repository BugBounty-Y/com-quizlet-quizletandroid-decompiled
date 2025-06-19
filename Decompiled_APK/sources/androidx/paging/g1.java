package androidx.paging;

import java.util.Arrays;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g1 {
    public static final g1 d = new g1(0, kotlin.collections.K.a);
    public final int[] a;
    public final List b;
    public final int c;

    public g1(int[] originalPageOffsets, List data, int i) {
        Intrinsics.checkNotNullParameter(originalPageOffsets, "originalPageOffsets");
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = originalPageOffsets;
        this.b = data;
        this.c = i;
        if (originalPageOffsets.length == 0) {
            throw new IllegalArgumentException("originalPageOffsets cannot be empty when constructing TransformablePage");
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || g1.class != obj.getClass()) {
            return false;
        }
        g1 g1Var = (g1) obj;
        return Arrays.equals(this.a, g1Var.a) && Intrinsics.b(this.b, g1Var.b) && this.c == g1Var.c;
    }

    public final int hashCode() {
        return (androidx.compose.animation.d0.f(Arrays.hashCode(this.a) * 31, 31, this.b) + this.c) * 31;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TransformablePage(originalPageOffsets=");
        sb.append(Arrays.toString(this.a));
        sb.append(", data=");
        sb.append(this.b);
        sb.append(", hintOriginalPageOffset=");
        return android.support.v4.media.session.a.r(sb, this.c, ", hintOriginalIndices=null)");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public g1(int i, List data) {
        this(new int[]{i}, data, i);
        Intrinsics.checkNotNullParameter(data, "data");
    }
}
