package com.quizlet.snowplow;

import android.content.Context;
import androidx.compose.ui.text.font.o;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.quizletandroid.u;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class SnowplowInitializer implements androidx.startup.b {
    /* JADX WARN: Removed duplicated region for block: B:7:0x001f  */
    /* JADX WARN: Type inference failed for: r12v7, types: [kotlinx.coroutines.flow.i, kotlinx.coroutines.flow.internal.a] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.snowplow.SnowplowInitializer r12, com.quizlet.snowplow.a r13, kotlin.coroutines.jvm.internal.c r14) {
        /*
            Method dump skipped, instructions count: 636
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.snowplow.SnowplowInitializer.a(com.quizlet.snowplow.SnowplowInitializer, com.quizlet.snowplow.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.startup.b
    public final Object create(Context context) {
        Trace traceA = com.google.firebase.perf.b.a("startup_SnowplowInitializer");
        Intrinsics.checkNotNullParameter(context, "context");
        Object objB = K6.b(a.class, context);
        Intrinsics.checkNotNullExpressionValue(objB, "get(...)");
        a aVar = (a) objB;
        u uVar = (u) aVar;
        ((com.google.firebase.perf.b) uVar.J.get()).getClass();
        Trace traceC = Trace.c("time_until_Snowplow_initialized");
        Intrinsics.checkNotNullExpressionValue(traceC, "newTrace(...)");
        traceC.start();
        E.A(uVar.V(), new o(C5041z.a, 12), null, new g(this, aVar, traceC, null), 2);
        traceA.stop();
        return Unit.a;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return K.a;
    }
}
