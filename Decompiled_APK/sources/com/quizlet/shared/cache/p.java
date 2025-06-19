package com.quizlet.shared.cache;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class p extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ s k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(s sVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = sVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new p(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((p) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x003e, code lost:
    
        if (((com.mayakapps.kache.InterfaceC4032a) r5).a(r4) == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r5) throws java.lang.Throwable {
        /*
            r4 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r4.j
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L1c
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L41
        L10:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L18:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L36
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            com.quizlet.shared.cache.s r5 = r4.k
            com.google.android.gms.measurement.internal.J r5 = r5.a
            r4.j = r3
            com.quizlet.shared.cache.d r1 = new com.quizlet.shared.cache.d
            r3 = 0
            r1.<init>(r5, r3)
            java.lang.Object r5 = r5.d
            kotlinx.coroutines.scheduling.e r5 = (kotlinx.coroutines.scheduling.e) r5
            java.lang.Object r5 = kotlinx.coroutines.E.J(r5, r1, r4)
            if (r5 != r0) goto L36
            goto L40
        L36:
            com.mayakapps.kache.a r5 = (com.mayakapps.kache.InterfaceC4032a) r5
            r4.j = r2
            java.lang.Object r5 = r5.a(r4)
            if (r5 != r0) goto L41
        L40:
            return r0
        L41:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.cache.p.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
