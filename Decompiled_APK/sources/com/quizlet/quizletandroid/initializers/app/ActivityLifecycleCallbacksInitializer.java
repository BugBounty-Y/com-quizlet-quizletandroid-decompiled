package com.quizlet.quizletandroid.initializers.app;

import android.app.Application;
import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.measurement.internal.C0;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.quizletandroid.u;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class ActivityLifecycleCallbacksInitializer implements androidx.startup.b {
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Trace traceA = com.google.firebase.perf.b.a("startup_ActivityLifecycleCallbacksInitializer");
        Intrinsics.checkNotNullParameter(context, "context");
        a aVar = (a) K6.b(a.class, context);
        Context applicationContext = context.getApplicationContext();
        Application application = applicationContext instanceof Application ? (Application) applicationContext : null;
        if (application != null) {
            application.registerActivityLifecycleCallbacks(new C0((com.quizlet.usecase.b) ((u) aVar).V0.get()));
        }
        traceA.stop();
        return Unit.a;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return K.a;
    }
}
