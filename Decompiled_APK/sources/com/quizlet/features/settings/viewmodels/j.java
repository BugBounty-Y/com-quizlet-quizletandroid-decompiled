package com.quizlet.features.settings.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ k k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(k kVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0052, code lost:
    
        if (r6.emit(r1, r5) == r0) goto L21;
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
            r2 = 2
            r3 = 1
            com.quizlet.features.settings.viewmodels.k r4 = r5.k
            if (r1 == 0) goto L22
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L55
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.r r6 = (kotlin.r) r6
            java.lang.Object r6 = r6.a
            goto L30
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.onetrust.otpublishers.headless.UI.fragment.q r6 = r4.b
            r5.j = r3
            java.lang.Object r6 = r6.o(r5)
            if (r6 != r0) goto L30
            goto L54
        L30:
            kotlin.p r1 = kotlin.r.b
            boolean r6 = r6 instanceof kotlin.q
            if (r6 != 0) goto L48
            kotlinx.coroutines.flow.s0 r6 = r4.c
        L38:
            java.lang.Object r0 = r6.getValue()
            r1 = r0
            com.quizlet.features.settings.data.states.s r1 = (com.quizlet.features.settings.data.states.s) r1
            com.quizlet.features.settings.data.states.n r1 = com.quizlet.features.settings.data.states.n.a
            boolean r0 = r6.k(r0, r1)
            if (r0 == 0) goto L38
            goto L55
        L48:
            kotlinx.coroutines.flow.d0 r6 = r4.d
            java.lang.Boolean r1 = java.lang.Boolean.TRUE
            r5.j = r2
            java.lang.Object r6 = r6.emit(r1, r5)
            if (r6 != r0) goto L55
        L54:
            return r0
        L55:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.settings.viewmodels.j.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
