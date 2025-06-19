package com.quizlet.quizletandroid.initializers.ads;

import android.app.Application;
import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.quizletandroid.u;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class MobileAdsInitializer implements androidx.startup.b {
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Trace traceA = com.google.firebase.perf.b.a("startup_MobileAdsInitializer");
        Intrinsics.checkNotNullParameter(context, "context");
        Object objB = K6.b(f.class, context);
        Intrinsics.checkNotNullExpressionValue(objB, "get(...)");
        f fVar = (f) objB;
        Context applicationContext = context.getApplicationContext();
        Application application = applicationContext instanceof Application ? (Application) applicationContext : null;
        if (application != null) {
            application.registerActivityLifecycleCallbacks(new com.quizlet.quizletandroid.ui.common.ads.nativeads.a(((u) fVar).c()));
        }
        u uVar = (u) fVar;
        E.A(uVar.Q(), null, null, new e(uVar, this, null), 3);
        traceA.stop();
        return Unit.a;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return K.a;
    }
}
