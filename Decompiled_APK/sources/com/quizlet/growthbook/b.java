package com.quizlet.growthbook;

import com.quizlet.data.model.V;
import com.sdk.growthbook.model.GBExperiment;
import com.sdk.growthbook.model.GBExperimentResult;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;
    public final /* synthetic */ V l;
    public final /* synthetic */ GBExperiment m;
    public final /* synthetic */ GBExperimentResult n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, V v, GBExperiment gBExperiment, GBExperimentResult gBExperimentResult, h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = v;
        this.m = gBExperiment;
        this.n = gBExperimentResult;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0095, code lost:
    
        if (r8 == r0) goto L20;
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
            com.quizlet.data.model.V r2 = r7.l
            r3 = 2
            r4 = 1
            com.quizlet.growthbook.e r5 = r7.k
            if (r1 == 0) goto L21
            if (r1 == r4) goto L1d
            if (r1 != r3) goto L15
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L98
        L15:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1d:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4c
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            dagger.internal.a r8 = r5.b
            java.lang.Object r8 = r8.get()
            com.quizlet.local.datastore.preferences.z r8 = (com.quizlet.local.datastore.preferences.C4589z) r8
            r7.j = r4
            r8.getClass()
            java.lang.String r1 = com.quizlet.local.datastore.preferences.C4589z.a(r2)
            androidx.datastore.preferences.core.f r1 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r1)
            androidx.datastore.core.h r8 = r8.a
            kotlinx.coroutines.flow.i r8 = r8.getData()
            com.quizlet.local.datastore.preferences.x r4 = new com.quizlet.local.datastore.preferences.x
            r6 = 0
            r4.<init>(r8, r1, r6)
            java.lang.Object r8 = kotlinx.coroutines.flow.e0.p(r4, r7)
            if (r8 != r0) goto L4c
            goto L97
        L4c:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            if (r8 != 0) goto L98
            dagger.internal.a r8 = r5.c
            java.lang.Object r8 = r8.get()
            com.quizlet.eventlogger.features.experimentation.ExperimentEnrollmentLogger r8 = (com.quizlet.eventlogger.features.experimentation.ExperimentEnrollmentLogger) r8
            com.sdk.growthbook.model.GBExperiment r1 = r7.m
            java.lang.String r1 = r1.getKey()
            com.sdk.growthbook.model.GBExperimentResult r4 = r7.n
            int r4 = r4.getVariationId()
            java.lang.String r4 = java.lang.String.valueOf(r4)
            r8.a(r1, r4)
            dagger.internal.a r8 = r5.b
            java.lang.Object r8 = r8.get()
            com.quizlet.local.datastore.preferences.z r8 = (com.quizlet.local.datastore.preferences.C4589z) r8
            r7.j = r3
            r8.getClass()
            java.lang.String r1 = com.quizlet.local.datastore.preferences.C4589z.a(r2)
            androidx.datastore.preferences.core.f r1 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r1)
            com.quizlet.local.datastore.preferences.u r2 = new com.quizlet.local.datastore.preferences.u
            r3 = 0
            r2.<init>(r1, r3)
            androidx.datastore.core.h r8 = r8.a
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_barcode.S6.d(r8, r2, r7)
            if (r8 != r0) goto L93
            goto L95
        L93:
            kotlin.Unit r8 = kotlin.Unit.a
        L95:
            if (r8 != r0) goto L98
        L97:
            return r0
        L98:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.growthbook.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
