package com.quizlet.growthbook.initializer;

import android.content.Context;
import android.os.Build;
import androidx.compose.ui.platform.C0960p;
import androidx.startup.b;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.growthbook.d;
import com.quizlet.growthbook.e;
import com.quizlet.quizletandroid.u;
import com.sdk.growthbook.GBSDKBuilder;
import com.sdk.growthbook.model.GBValuesKt;
import com.sdk.growthbook.network.GBNetworkDispatcherOkHttp;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class GrowthBookInitializer implements b {
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Trace traceA = com.google.firebase.perf.b.a("startup_GrowthBookInitializer");
        Intrinsics.checkNotNullParameter(context, "context");
        Object objB = K6.b(a.class, context);
        Intrinsics.checkNotNullExpressionValue(objB, "get(...)");
        e eVar = (e) ((com.quizlet.growthbook.contracts.a) ((u) ((a) objB)).y0.get());
        LinkedHashMap attributes = eVar.h;
        attributes.put("qz_app_version", GBValuesKt.toGbString("9.34.3"));
        attributes.put("os_version", GBValuesKt.toGbString(Build.VERSION.RELEASE));
        attributes.put("platform", GBValuesKt.toGbString("Android"));
        attributes.put("device_id", GBValuesKt.toGbString(eVar.d));
        eVar.f.getClass();
        Trace traceC = Trace.c("QGrowthBook_setup");
        eVar.j = traceC;
        traceC.start();
        C0960p trackingCallback = new C0960p(2, eVar, e.class, "getTrackingCallback", "getTrackingCallback(Lcom/sdk/growthbook/model/GBExperiment;Lcom/sdk/growthbook/model/GBExperimentResult;)V", 0, 19);
        GBNetworkDispatcherOkHttp networkDispatcher = new GBNetworkDispatcherOkHttp(null, false, 3, null);
        Intrinsics.checkNotNullParameter("sdk-sJHy6gRWRprzUkjR", DTBMetricsConfiguration.APSMETRICS_APIKEY);
        Intrinsics.checkNotNullParameter("55TP7Es/PSnvTN5kONR4JQ==", "encryptionKey");
        Intrinsics.checkNotNullParameter("https://cdn.growthbook.io/", "hostURL");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(trackingCallback, "trackingCallback");
        Intrinsics.checkNotNullParameter(networkDispatcher, "networkDispatcher");
        eVar.g = new GBSDKBuilder("sdk-sJHy6gRWRprzUkjR", "https://cdn.growthbook.io/", networkDispatcher, attributes, "55TP7Es/PSnvTN5kONR4JQ==", trackingCallback, false, false, 192, null).setRefreshHandler(new C0960p(2, eVar, e.class, "getRefreshHandler", "getRefreshHandler(ZLcom/sdk/growthbook/utils/GBError;)V", 0, 20)).initialize();
        E.A(eVar.e, null, null, new d(eVar, null), 3);
        traceA.stop();
        return Unit.a;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return K.a;
    }
}
