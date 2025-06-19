package androidx.privacysandbox.ads.adservices.measurement;

import android.adservices.measurement.MeasurementManager;
import android.content.Context;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class b extends e {
    /* JADX WARN: Illegal instructions before constructor call */
    public b(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        MeasurementManager measurementManager = MeasurementManager.get(context);
        Intrinsics.checkNotNullExpressionValue(measurementManager, "get(context)");
        super(measurementManager);
    }
}
