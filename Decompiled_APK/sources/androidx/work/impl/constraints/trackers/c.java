package androidx.work.impl.constraints.trackers;

import androidx.work.z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class c {
    public static final String a;

    static {
        String strE = z.e("BatteryNotLowTracker");
        Intrinsics.checkNotNullExpressionValue(strE, "tagWithPrefix(\"BatteryNotLowTracker\")");
        a = strE;
    }
}
