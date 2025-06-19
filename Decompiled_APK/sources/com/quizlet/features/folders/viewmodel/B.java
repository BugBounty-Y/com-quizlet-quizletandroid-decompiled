package com.quizlet.features.folders.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class B extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ N k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(N n, kotlin.coroutines.h hVar, boolean z) {
        super(2, hVar);
        this.k = n;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new B(this.k, hVar, this.l);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x004e, code lost:
    
        if (r1.emit(r7, r6) == r0) goto L22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x005f, code lost:
    
        if (r1.emit(r7, r6) == r0) goto L22;
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
            if (r1 == 0) goto L22
            if (r1 == r5) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            goto L1a
        L12:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L62
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L3a
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlinx.coroutines.flow.s0 r7 = r2.H
            java.lang.Object r7 = r7.getValue()
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            r6.j = r5
            java.lang.Object r7 = com.quizlet.features.folders.viewmodel.N.D(r2, r7, r6)
            if (r7 != r0) goto L3a
            goto L61
        L3a:
            boolean r7 = r6.l
            kotlinx.coroutines.flow.d0 r1 = r2.E
            if (r7 == 0) goto L51
            com.quizlet.features.folders.data.B0 r7 = new com.quizlet.features.folders.data.B0
            r2 = 2132017478(0x7f140146, float:1.9673236E38)
            r7.<init>(r2)
            r6.j = r4
            java.lang.Object r7 = r1.emit(r7, r6)
            if (r7 != r0) goto L62
            goto L61
        L51:
            com.quizlet.features.folders.data.B0 r7 = new com.quizlet.features.folders.data.B0
            r2 = 2132017501(0x7f14015d, float:1.9673282E38)
            r7.<init>(r2)
            r6.j = r3
            java.lang.Object r7 = r1.emit(r7, r6)
            if (r7 != r0) goto L62
        L61:
            return r0
        L62:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.B.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
