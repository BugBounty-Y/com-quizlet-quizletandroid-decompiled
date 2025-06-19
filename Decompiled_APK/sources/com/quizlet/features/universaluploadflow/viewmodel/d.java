package com.quizlet.features.universaluploadflow.viewmodel;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ g k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(g gVar, h hVar) {
        super(2, hVar);
        this.k = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x002f, code lost:
    
        if (com.quizlet.features.universaluploadflow.viewmodel.g.A(r5, r4) == r0) goto L20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x003e, code lost:
    
        if (r5.E(r4) == r0) goto L20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0040, code lost:
    
        return r0;
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
            int r1 = r4.j
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L18
            if (r1 == r3) goto Lc
            if (r1 != r2) goto L10
        Lc:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L41
        L10:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L18:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            com.quizlet.features.universaluploadflow.viewmodel.g r5 = r4.k
            com.quizlet.data.model.m2 r1 = r5.i
            int r1 = r1.ordinal()
            if (r1 == 0) goto L38
            if (r1 == r3) goto L38
            if (r1 != r2) goto L32
            r4.j = r2
            java.lang.Object r5 = com.quizlet.features.universaluploadflow.viewmodel.g.A(r5, r4)
            if (r5 != r0) goto L41
            goto L40
        L32:
            kotlin.NoWhenBranchMatchedException r5 = new kotlin.NoWhenBranchMatchedException
            r5.<init>()
            throw r5
        L38:
            r4.j = r3
            java.lang.Object r5 = r5.E(r4)
            if (r5 != r0) goto L41
        L40:
            return r0
        L41:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.universaluploadflow.viewmodel.d.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
