package com.quizlet.features.setpage.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class N extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ P k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public N(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new N(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((N) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Can't wrap try/catch for region: R(9:0|2|(1:(1:(6:6|20|31|21|22|23)(2:7|8))(1:9))(3:10|(0)|19)|13|29|14|15|17|(1:(0))) */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0078, code lost:
    
        r1 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x008e, code lost:
    
        if (r8 == r0) goto L19;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) throws android.content.pm.PackageManager.NameNotFoundException {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            r2 = 2
            r3 = 1
            com.quizlet.features.setpage.viewmodel.P r4 = r7.k
            if (r1 == 0) goto L1f
            if (r1 == r3) goto L1b
            if (r1 != r2) goto L13
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L91
        L13:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L2f
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            io.reactivex.rxjava3.internal.operators.flowable.b r8 = r4.E()
            r7.j = r3
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r8, r7)
            if (r8 != r0) goto L2f
            goto L90
        L2f:
            java.lang.String r1 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r1)
            com.quizlet.infra.legacysyncengine.features.properties.d r8 = (com.quizlet.infra.legacysyncengine.features.properties.d) r8
            com.lyft.android.scissors.b r1 = r4.t
            r7.j = r2
            androidx.work.impl.model.c r2 = r4.d
            r1.getClass()
            io.reactivex.rxjava3.core.p r3 = r8.a()
            com.quizlet.infra.legacysyncengine.features.properties.c r5 = com.quizlet.infra.legacysyncengine.features.properties.c.h
            io.reactivex.rxjava3.internal.operators.single.g r3 = r3.g(r5)
            java.lang.String r5 = "map(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r5)
            io.reactivex.rxjava3.core.p r8 = r8.a()
            com.quizlet.infra.legacysyncengine.features.properties.c r6 = com.quizlet.infra.legacysyncengine.features.properties.c.g
            io.reactivex.rxjava3.internal.operators.single.g r8 = r8.g(r6)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r5)
            io.reactivex.rxjava3.internal.operators.single.g r8 = com.google.android.gms.dynamite.d.f(r3, r8)
            io.reactivex.rxjava3.internal.operators.single.g r2 = r2.u()
            io.reactivex.rxjava3.internal.operators.single.g r2 = com.google.android.gms.dynamite.d.e(r2)
            io.reactivex.rxjava3.internal.operators.single.g r8 = com.google.android.gms.dynamite.d.b(r8, r2)
            java.lang.Object r1 = r1.b
            android.content.pm.PackageManager r1 = (android.content.pm.PackageManager) r1
            java.lang.String r2 = "com.whatsapp"
            r3 = 128(0x80, float:1.8E-43)
            r1.getPackageInfo(r2, r3)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L78
            r1 = 1
            goto L79
        L78:
            r1 = 0
        L79:
            java.lang.Boolean r1 = java.lang.Boolean.valueOf(r1)
            io.reactivex.rxjava3.internal.operators.flowable.b r1 = io.reactivex.rxjava3.core.p.f(r1)
            java.lang.String r2 = "just(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)
            io.reactivex.rxjava3.internal.operators.single.g r8 = com.google.android.gms.dynamite.d.b(r8, r1)
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r8, r7)
            if (r8 != r0) goto L91
        L90:
            return r0
        L91:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            io.reactivex.rxjava3.internal.operators.flowable.b r0 = r4.E()
            com.google.firebase.messaging.p r1 = new com.google.firebase.messaging.p
            r2 = 22
            r1.<init>(r4, r2)
            io.reactivex.rxjava3.internal.operators.single.g r0 = r0.e(r1)
            java.lang.String r1 = "flatMap(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r1)
            com.quizlet.features.setpage.viewmodel.k r1 = com.quizlet.features.setpage.viewmodel.C4437k.c
            com.quizlet.features.setpage.viewmodel.M r2 = new com.quizlet.features.setpage.viewmodel.M
            r2.<init>(r4, r8)
            com.quizlet.infra.legacysyncengine.net.request.g r8 = io.reactivex.rxjava3.internal.functions.d.e
            io.reactivex.rxjava3.internal.functions.b r3 = io.reactivex.rxjava3.internal.functions.d.c
            io.reactivex.rxjava3.internal.operators.completable.l r4 = new io.reactivex.rxjava3.internal.operators.completable.l
            r4.<init>(r2, r8, r3)
            io.reactivex.rxjava3.internal.operators.maybe.g r8 = new io.reactivex.rxjava3.internal.operators.maybe.g     // Catch: java.lang.Throwable -> Lc7 java.lang.NullPointerException -> Ld6
            r2 = 0
            r8.<init>(r4, r1, r2)     // Catch: java.lang.Throwable -> Lc7 java.lang.NullPointerException -> Ld6
            r0.j(r8)     // Catch: java.lang.Throwable -> Lc7 java.lang.NullPointerException -> Ld6
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        Lc7:
            r8 = move-exception
            com.google.android.gms.internal.mlkit_vision_barcode.x7.b(r8)
            java.lang.NullPointerException r0 = new java.lang.NullPointerException
            java.lang.String r1 = "subscribeActual failed"
            r0.<init>(r1)
            r0.initCause(r8)
            throw r0
        Ld6:
            r8 = move-exception
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.viewmodel.N.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
