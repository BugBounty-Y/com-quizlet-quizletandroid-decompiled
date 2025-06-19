package com.quizlet.prebid;

import android.content.Context;
import androidx.startup.b;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.quizletandroid.u;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.prebid.mobile.Host;
import org.prebid.mobile.PrebidMobile;
import org.prebid.mobile.rendering.sdk.InitializationNotifier;
import org.prebid.mobile.rendering.sdk.PrebidContextHolder;
import org.prebid.mobile.rendering.sdk.SdkInitializer;

@Metadata
/* loaded from: classes3.dex */
public final class PrebidInitializer implements b {
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Trace traceA = com.google.firebase.perf.b.a("startup_PrebidInitializer");
        Intrinsics.checkNotNullParameter(context, "context");
        Object objB = K6.b(com.quizlet.prebid.di.a.class, context);
        Intrinsics.checkNotNullExpressionValue(objB, "get(...)");
        u uVar = (u) ((com.quizlet.prebid.di.a) objB);
        uVar.getClass();
        S6.c(com.quizlet.quizletandroid.provider.a.a);
        PrebidMobile.LogLevel logLevel = PrebidMobile.LogLevel.NONE;
        Context context2 = uVar.q();
        Intrinsics.checkNotNullParameter(context2, "context");
        a aVar = new a(context2);
        Intrinsics.checkNotNullParameter(logLevel, "logLevel");
        int i = PrebidMobile.a;
        if (PrebidContextHolder.a() == null || !InitializationNotifier.b) {
            PrebidMobile.b = "24194-mobilewrapper-android-0";
            com.quizlet.infra.legacysyncengine.models.serializers.a aVar2 = new com.quizlet.infra.legacysyncengine.models.serializers.a(14);
            Host host = Host.b;
            if (host.equals(host)) {
                host.a = "https://prebid-server.rubiconproject.com/openrtb2/auction";
            }
            PrebidMobile.c = host;
            SdkInitializer.a(aVar.a, aVar2);
        }
        traceA.stop();
        return Unit.a;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return new ArrayList();
    }
}
