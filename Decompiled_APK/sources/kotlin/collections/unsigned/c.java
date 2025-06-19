package kotlin.collections.unsigned;

import java.util.List;
import kotlin.collections.C4930v;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* loaded from: classes3.dex */
public class c extends b {
    public static List a(long[] slice, IntRange indices) {
        Intrinsics.checkNotNullParameter(slice, "$this$slice");
        Intrinsics.checkNotNullParameter(indices, "indices");
        if (indices.isEmpty()) {
            return K.a;
        }
        long[] asList = C4930v.m(slice, indices.a, indices.b + 1);
        Intrinsics.checkNotNullParameter(asList, "storage");
        Intrinsics.checkNotNullParameter(asList, "$this$asList");
        return new a(asList);
    }
}
