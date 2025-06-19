package kotlin.time;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class e {
    public static final double a(double d, d sourceUnit, d targetUnit) {
        Intrinsics.checkNotNullParameter(sourceUnit, "sourceUnit");
        Intrinsics.checkNotNullParameter(targetUnit, "targetUnit");
        long jConvert = targetUnit.a.convert(1L, sourceUnit.a);
        return jConvert > 0 ? d * jConvert : d / sourceUnit.a.convert(1L, targetUnit.a);
    }

    public static final long b(long j, d sourceUnit, d targetUnit) {
        Intrinsics.checkNotNullParameter(sourceUnit, "sourceUnit");
        Intrinsics.checkNotNullParameter(targetUnit, "targetUnit");
        return targetUnit.a.convert(j, sourceUnit.a);
    }

    public static final long c(long j, d sourceUnit, d targetUnit) {
        Intrinsics.checkNotNullParameter(sourceUnit, "sourceUnit");
        Intrinsics.checkNotNullParameter(targetUnit, "targetUnit");
        return targetUnit.a.convert(j, sourceUnit.a);
    }
}
