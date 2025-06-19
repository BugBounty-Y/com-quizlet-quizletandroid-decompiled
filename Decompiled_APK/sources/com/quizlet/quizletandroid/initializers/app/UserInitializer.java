package com.quizlet.quizletandroid.initializers.app;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.quizletandroid.u;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;
import kotlinx.coroutines.internal.m;

@Metadata
/* loaded from: classes3.dex */
public final class UserInitializer implements androidx.startup.b {
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Trace traceA = com.google.firebase.perf.b.a("startup_UserInitializer");
        Intrinsics.checkNotNullParameter(context, "context");
        Object objB = K6.b(g.class, context);
        Intrinsics.checkNotNullExpressionValue(objB, "get(...)");
        g gVar = (g) objB;
        ((u) gVar).getClass();
        kotlinx.coroutines.scheduling.e eVar = O.a;
        kotlinx.coroutines.android.d dispatcher = m.a;
        S6.c(dispatcher);
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        E.A(E.c(dispatcher), null, null, new h(gVar, null), 3);
        traceA.stop();
        return Unit.a;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return K.a;
    }
}
