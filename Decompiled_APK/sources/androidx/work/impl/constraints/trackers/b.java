package androidx.work.impl.constraints.trackers;

import androidx.work.z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class b {
    public static final String a;

    static {
        String strE = z.e("BatteryChrgTracker");
        Intrinsics.checkNotNullExpressionValue(strE, "tagWithPrefix(\"BatteryChrgTracker\")");
        a = strE;
    }
}
