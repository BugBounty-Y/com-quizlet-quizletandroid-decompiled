package com.quizlet.features.setpage.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public androidx.work.impl.model.c j;
    public int k;
    public final /* synthetic */ P l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new s(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((s) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x0049, code lost:
    
        if (r7 == r0) goto L17;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.k
            r2 = 0
            com.quizlet.features.setpage.viewmodel.P r3 = r6.l
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L21
            if (r1 == r5) goto L1b
            if (r1 != r4) goto L13
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4c
        L13:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1b:
            androidx.work.impl.model.c r1 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L35
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            androidx.work.impl.model.c r1 = r3.d
            io.reactivex.rxjava3.internal.operators.single.g r7 = r1.r()
            r6.j = r1
            r6.k = r5
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r7, r6)
            if (r7 != r0) goto L35
            goto L4b
        L35:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 != 0) goto L55
            io.reactivex.rxjava3.internal.operators.single.g r7 = r1.u()
            r6.j = r2
            r6.k = r4
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r7, r6)
            if (r7 != r0) goto L4c
        L4b:
            return r0
        L4c:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 != 0) goto L55
            goto L56
        L55:
            r5 = 0
        L56:
            kotlinx.coroutines.flow.s0 r7 = r3.L1
        L58:
            java.lang.Object r0 = r7.getValue()
            r1 = r0
            com.quizlet.features.setpage.screenstates.F r1 = (com.quizlet.features.setpage.screenstates.F) r1
            r3 = 5
            com.quizlet.features.setpage.screenstates.F r1 = com.quizlet.features.setpage.screenstates.F.a(r1, r5, r2, r3)
            boolean r0 = r7.k(r0, r1)
            if (r0 == 0) goto L58
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.viewmodel.s.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
