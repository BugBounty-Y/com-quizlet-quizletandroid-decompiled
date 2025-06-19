package com.quizlet.features.setpage.offline;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ k k;
    public final /* synthetic */ long l;
    public final /* synthetic */ boolean m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(k kVar, long j, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = kVar;
        this.l = j;
        this.m = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x005a, code lost:
    
        if (r6 == r0) goto L22;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.j
            com.quizlet.features.setpage.offline.k r2 = r5.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L5d
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L3d
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.featuregate.features.folder.e r6 = r2.b
            androidx.work.impl.model.c r6 = r6.a
            io.reactivex.rxjava3.internal.operators.single.g r6 = r6.r()
            com.quizlet.offline.b r1 = com.quizlet.offline.b.a
            io.reactivex.rxjava3.internal.operators.single.g r6 = r6.e(r1)
            java.lang.String r1 = "flatMap(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r1)
            r5.j = r4
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r6, r5)
            if (r6 != r0) goto L3d
            goto L5c
        L3d:
            com.quizlet.offline.a r6 = (com.quizlet.offline.a) r6
            int r6 = r6.ordinal()
            if (r6 == 0) goto L50
            if (r6 != r4) goto L4a
            com.quizlet.features.setpage.header.data.g r6 = com.quizlet.features.setpage.header.data.g.a
            return r6
        L4a:
            kotlin.NoWhenBranchMatchedException r6 = new kotlin.NoWhenBranchMatchedException
            r6.<init>()
            throw r6
        L50:
            r5.j = r3
            long r3 = r5.l
            boolean r6 = r5.m
            java.lang.Object r6 = com.quizlet.features.setpage.offline.k.a(r2, r3, r6, r5)
            if (r6 != r0) goto L5d
        L5c:
            return r0
        L5d:
            com.quizlet.features.setpage.header.data.h r6 = (com.quizlet.features.setpage.header.data.h) r6
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.offline.e.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
