package com.quizlet.comscore;

import android.content.Context;
import androidx.startup.b;
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
/* loaded from: classes2.dex */
public final class ComscoreInitializer implements b {
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Trace traceA = com.google.firebase.perf.b.a("startup_ComscoreInitializer");
        Intrinsics.checkNotNullParameter(context, "context");
        Object objB = K6.b(com.quizlet.comscore.di.a.class, context);
        Intrinsics.checkNotNullExpressionValue(objB, "get(...)");
        u uVar = (u) ((com.quizlet.comscore.di.a) objB);
        E.A(uVar.Q(), null, null, new a(uVar, this, context, null), 3);
        traceA.stop();
        return Unit.a;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return K.a;
    }
}
