package com.quizlet.snowplow;

import com.google.firebase.perf.metrics.Trace;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class g extends i implements Function2 {
    public int j;
    public final /* synthetic */ SnowplowInitializer k;
    public final /* synthetic */ a l;
    public final /* synthetic */ Trace m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(SnowplowInitializer snowplowInitializer, a aVar, Trace trace, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = snowplowInitializer;
        this.l = aVar;
        this.m = trace;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0073, code lost:
    
        if (r8 == r0) goto L21;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            com.quizlet.snowplow.a r2 = r7.l
            r3 = 1
            r4 = 2
            if (r1 == 0) goto L1e
            if (r1 == r3) goto L1a
            if (r1 != r4) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L76
        L12:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L2c
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r7.j = r3
            com.quizlet.snowplow.SnowplowInitializer r8 = r7.k
            java.lang.Object r8 = com.quizlet.snowplow.SnowplowInitializer.a(r8, r2, r7)
            if (r8 != r0) goto L2c
            goto L75
        L2c:
            com.snowplowanalytics.core.tracker.o r8 = (com.snowplowanalytics.core.tracker.o) r8
            com.quizlet.quizletandroid.u r2 = (com.quizlet.quizletandroid.u) r2
            dagger.internal.c r1 = r2.o
            java.lang.Object r1 = r1.get()
            com.quizlet.usecase.a r1 = (com.quizlet.usecase.a) r1
            kotlinx.coroutines.flow.internal.a r1 = r1.a
            com.quizlet.analytics.marketing.appsflyer.d r2 = new com.quizlet.analytics.marketing.appsflyer.d
            kotlinx.coroutines.flow.W r1 = (kotlinx.coroutines.flow.W) r1
            r3 = 8
            r2.<init>(r1, r3)
            kotlinx.coroutines.flow.i r1 = kotlinx.coroutines.flow.e0.m(r2)
            com.quizlet.snowplow.d r2 = new com.quizlet.snowplow.d
            r3 = 0
            r2.<init>(r4, r3)
            androidx.compose.foundation.text.input.internal.b r3 = new androidx.compose.foundation.text.input.internal.b
            com.google.firebase.perf.metrics.Trace r5 = r7.m
            r6 = 19
            r3.<init>(r5, r6)
            r7.j = r4
            androidx.paging.I0 r4 = new androidx.paging.I0
            r5 = 2
            r4.<init>(r3, r2, r5)
            androidx.compose.foundation.text.i0 r2 = new androidx.compose.foundation.text.i0
            r3 = 27
            r2.<init>(r3, r4, r8)
            java.lang.Object r8 = r1.b(r2, r7)
            if (r8 != r0) goto L6c
            goto L6e
        L6c:
            kotlin.Unit r8 = kotlin.Unit.a
        L6e:
            if (r8 != r0) goto L71
            goto L73
        L71:
            kotlin.Unit r8 = kotlin.Unit.a
        L73:
            if (r8 != r0) goto L76
        L75:
            return r0
        L76:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.snowplow.g.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
