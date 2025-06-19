package com.quizlet.features.notes.paywall;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public s0 j;
    public int k;
    public final /* synthetic */ l l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x003a, code lost:
    
        if (kotlin.Unit.a == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r5) {
        /*
            r4 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r4.k
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L1e
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L3d
        L10:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L18:
            kotlinx.coroutines.flow.s0 r1 = r4.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L30
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            com.quizlet.features.notes.paywall.l r5 = r4.l
            kotlinx.coroutines.flow.s0 r1 = r5.e
            r4.j = r1
            r4.k = r3
            java.lang.Object r5 = com.quizlet.features.notes.paywall.l.A(r5, r4)
            if (r5 != r0) goto L30
            goto L3c
        L30:
            r3 = 0
            r4.j = r3
            r4.k = r2
            r1.l(r5)
            kotlin.Unit r5 = kotlin.Unit.a
            if (r5 != r0) goto L3d
        L3c:
            return r0
        L3d:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.paywall.j.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
