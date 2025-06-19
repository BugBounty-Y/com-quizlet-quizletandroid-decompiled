package com.quizlet.features.folders.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.folders.viewmodel.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4325f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public int k;
    public final /* synthetic */ N l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4325f(N n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4325f(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4325f) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x007c, code lost:
    
        if (r10.emit(r2, r9) == r0) goto L25;
     */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0065  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.k
            com.quizlet.features.folders.viewmodel.N r2 = r9.l
            r3 = 3
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L2c
            if (r1 == r5) goto L23
            if (r1 == r4) goto L1d
            if (r1 != r3) goto L15
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L7f
        L15:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L1d:
            java.lang.Object r1 = r9.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L5f
        L23:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlin.r r10 = (kotlin.r) r10
            java.lang.Object r10 = r10.a
        L2a:
            r1 = r10
            goto L3c
        L2c:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r9.k = r5
            com.quizlet.data.interactor.folder.f r10 = r2.k
            long r5 = r2.r
            java.lang.Object r10 = r10.a(r5, r9)
            if (r10 != r0) goto L2a
            goto L7e
        L3c:
            kotlin.p r10 = kotlin.r.b
            boolean r10 = r1 instanceof kotlin.q
            if (r10 != 0) goto L5f
            r10 = r1
            com.quizlet.data.model.d0 r10 = (com.quizlet.data.model.AbstractC4119d0) r10
            r5 = 0
            r2.O(r5)
            kotlinx.coroutines.flow.d0 r5 = r2.A
            com.quizlet.features.folders.data.n0 r6 = new com.quizlet.features.folders.data.n0
            long r7 = r10.a()
            r6.<init>(r7)
            r9.j = r1
            r9.k = r4
            java.lang.Object r10 = r5.emit(r6, r9)
            if (r10 != r0) goto L5f
            goto L7e
        L5f:
            java.lang.Throwable r10 = kotlin.r.a(r1)
            if (r10 == 0) goto L7f
            com.quizlet.features.folders.data.a r10 = com.quizlet.features.folders.data.EnumC4270a.a
            r2.O(r10)
            kotlinx.coroutines.flow.d0 r10 = r2.E
            com.quizlet.features.folders.data.B0 r2 = new com.quizlet.features.folders.data.B0
            r4 = 2132017593(0x7f1401b9, float:1.9673469E38)
            r2.<init>(r4)
            r9.j = r1
            r9.k = r3
            java.lang.Object r10 = r10.emit(r2, r9)
            if (r10 != r0) goto L7f
        L7e:
            return r0
        L7f:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.C4325f.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
