package com.quizlet.quizletandroid.initializers.app;

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
public final class ComponentCallbacksInitializer implements androidx.startup.b {
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Trace traceA = com.google.firebase.perf.b.a("startup_ComponentCallbacksInitializer");
        Intrinsics.checkNotNullParameter(context, "context");
        Object objB = K6.b(c.class, context);
        Intrinsics.checkNotNullExpressionValue(objB, "get(...)");
        u uVar = (u) ((c) objB);
        E.A(uVar.V(), null, null, new b(context, uVar, null), 3);
        traceA.stop();
        return Unit.a;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return K.a;
    }
}
