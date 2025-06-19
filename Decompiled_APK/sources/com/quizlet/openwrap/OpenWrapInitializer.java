package com.quizlet.openwrap;

import android.content.Context;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.firebase.perf.metrics.Trace;
import com.pubmatic.sdk.common.a;
import com.pubmatic.sdk.common.models.d;
import com.quizlet.quizletandroid.u;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class OpenWrapInitializer implements androidx.startup.b {
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Trace traceA = com.google.firebase.perf.b.a("startup_OpenWrapInitializer");
        Intrinsics.checkNotNullParameter(context, "context");
        Object objB = K6.b(com.quizlet.openwrap.di.a.class, context);
        Intrinsics.checkNotNullExpressionValue(objB, "get(...)");
        ((u) ((com.quizlet.openwrap.di.a) objB)).getClass();
        a aVar = new a();
        S6.c(com.quizlet.quizletandroid.provider.a.a);
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        a.EnumC0007a level = a.EnumC0007a.Off;
        Intrinsics.checkNotNullParameter(level, "level");
        com.pubmatic.sdk.common.a.setLogLevel(level);
        Intrinsics.checkNotNullParameter("https://play.google.com/store/apps/details?id=com.quizlet.quizletandroid", DTBMetricsConfiguration.APSMETRICS_URL);
        d info = new d();
        info.setStoreURL(new URL("https://play.google.com/store/apps/details?id=com.quizlet.quizletandroid"));
        Intrinsics.checkNotNullParameter(info, "info");
        com.pubmatic.sdk.common.a.setApplicationInfo(info);
        traceA.stop();
        return Unit.a;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return new ArrayList();
    }
}
