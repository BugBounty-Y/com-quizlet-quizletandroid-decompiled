package com.quizlet.features.folders.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class F extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ N l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(N n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        F f = new F(this.l, hVar);
        f.k = obj;
        return f;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((F) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0040, code lost:
    
        if (r1.emit(r5, r4) == r0) goto L15;
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
            if (r1 == 0) goto L20
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L43
        L10:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L18:
            java.lang.Object r1 = r4.k
            kotlinx.coroutines.flow.j r1 = (kotlinx.coroutines.flow.InterfaceC5002j) r1
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L37
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            java.lang.Object r5 = r4.k
            r1 = r5
            kotlinx.coroutines.flow.j r1 = (kotlinx.coroutines.flow.InterfaceC5002j) r1
            com.quizlet.features.folders.viewmodel.N r5 = r4.l
            com.quizlet.data.repository.user.a r5 = r5.q
            r4.k = r1
            r4.j = r3
            java.lang.Object r5 = r5.j(r4)
            if (r5 != r0) goto L37
            goto L42
        L37:
            r3 = 0
            r4.k = r3
            r4.j = r2
            java.lang.Object r5 = r1.emit(r5, r4)
            if (r5 != r0) goto L43
        L42:
            return r0
        L43:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.F.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
