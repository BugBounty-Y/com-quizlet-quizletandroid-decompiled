package com.quizlet.shared.cache;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ s k;
    public final /* synthetic */ serialization.e l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(s sVar, serialization.e eVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = sVar;
        this.l = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x005c, code lost:
    
        if (((com.mayakapps.kache.InterfaceC4032a) r6).c(r1, r5) == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) throws java.lang.Throwable {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.j
            com.quizlet.shared.cache.s r2 = r5.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L5f
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L36
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.google.android.gms.measurement.internal.J r6 = r2.a
            r5.j = r4
            com.quizlet.shared.cache.d r1 = new com.quizlet.shared.cache.d
            r4 = 0
            r1.<init>(r6, r4)
            java.lang.Object r6 = r6.d
            kotlinx.coroutines.scheduling.e r6 = (kotlinx.coroutines.scheduling.e) r6
            java.lang.Object r6 = kotlinx.coroutines.E.J(r6, r1, r5)
            if (r6 != r0) goto L36
            goto L5e
        L36:
            com.mayakapps.kache.a r6 = (com.mayakapps.kache.InterfaceC4032a) r6
            com.quizlet.remote.model.set.d r1 = r2.c
            java.lang.Object r1 = r1.a
            com.quizlet.quizletandroid.k r1 = (com.quizlet.quizletandroid.k) r1
            serialization.e r2 = r5.l
            r1.getClass()
            java.lang.String r4 = "value"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r4)
            serialization.d r4 = serialization.e.Companion
            kotlinx.serialization.KSerializer r4 = r4.serializer()
            java.lang.Object r1 = r1.b
            kotlinx.serialization.json.c r1 = (kotlinx.serialization.json.c) r1
            java.lang.String r1 = r1.c(r4, r2)
            r5.j = r3
            java.lang.Object r6 = r6.c(r1, r5)
            if (r6 != r0) goto L5f
        L5e:
            return r0
        L5f:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.cache.r.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
