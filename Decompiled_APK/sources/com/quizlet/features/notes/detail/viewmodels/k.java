package com.quizlet.features.notes.detail.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ v k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(v vVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x003a, code lost:
    
        if (r6.emit(r1, r5) == r0) goto L15;
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
            com.quizlet.features.notes.detail.viewmodels.v r2 = r5.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L3d
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L30
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.features.notes.data.c r6 = new com.quizlet.features.notes.data.c
            r1 = 6
            r6.<init>(r1)
            r5.j = r4
            java.lang.Object r6 = r2.G(r6, r5)
            if (r6 != r0) goto L30
            goto L3c
        L30:
            kotlinx.coroutines.flow.d0 r6 = r2.t
            com.quizlet.features.notes.detail.menu.h r1 = com.quizlet.features.notes.detail.menu.h.a
            r5.j = r3
            java.lang.Object r6 = r6.emit(r1, r5)
            if (r6 != r0) goto L3d
        L3c:
            return r0
        L3d:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.detail.viewmodels.k.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
