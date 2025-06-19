package com.quizlet.features.folders.viewmodel;

import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.folders.viewmodel.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4332m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ N k;
    public final /* synthetic */ List l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4332m(N n, List list, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = n;
        this.l = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4332m(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4332m) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x005c, code lost:
    
        if (com.quizlet.features.folders.viewmodel.N.E(r2, r6.l, r6) != r0) goto L23;
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
            int r1 = r6.j
            com.quizlet.features.folders.viewmodel.N r2 = r6.k
            r3 = 3
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L25
            if (r1 == r5) goto L21
            if (r1 == r4) goto L1d
            if (r1 != r3) goto L15
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5f
        L15:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1d:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L54
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L3d
        L25:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlinx.coroutines.flow.s0 r7 = r2.H
            java.lang.Object r7 = r7.getValue()
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            r6.j = r5
            java.lang.Object r7 = com.quizlet.features.folders.viewmodel.N.D(r2, r7, r6)
            if (r7 != r0) goto L3d
            goto L5e
        L3d:
            com.quizlet.data.model.I1 r7 = r2.K
            if (r7 != 0) goto L54
            kotlinx.coroutines.flow.d0 r7 = r2.E
            com.quizlet.features.folders.data.B0 r1 = new com.quizlet.features.folders.data.B0
            r5 = 2132019853(0x7f140a8d, float:1.9678053E38)
            r1.<init>(r5)
            r6.j = r4
            java.lang.Object r7 = r7.emit(r1, r6)
            if (r7 != r0) goto L54
            goto L5e
        L54:
            r6.j = r3
            java.util.List r7 = r6.l
            java.lang.Object r7 = com.quizlet.features.folders.viewmodel.N.E(r2, r7, r6)
            if (r7 != r0) goto L5f
        L5e:
            return r0
        L5f:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.C4332m.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
