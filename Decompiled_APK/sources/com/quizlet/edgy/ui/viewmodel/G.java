package com.quizlet.edgy.ui.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class G extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ M k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(M m, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = m;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new G(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((G) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0034, code lost:
    
        if (r7 == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) throws java.lang.Throwable {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.j
            com.quizlet.edgy.ui.viewmodel.M r2 = r6.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L37
        L12:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L2c
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r6.j = r4
            r4 = 300(0x12c, double:1.48E-321)
            java.lang.Object r7 = kotlinx.coroutines.E.n(r4, r6)
            if (r7 != r0) goto L2c
            goto L36
        L2c:
            r6.j = r3
            java.lang.String r7 = r6.l
            java.io.Serializable r7 = com.quizlet.edgy.ui.viewmodel.M.A(r2, r7, r6)
            if (r7 != r0) goto L37
        L36:
            return r0
        L37:
            java.util.List r7 = (java.util.List) r7
            com.quizlet.edgy.ui.recyclerview.adapter.i r0 = r2.k
            if (r0 == 0) goto L51
        L3d:
            kotlinx.coroutines.flow.s0 r1 = r2.p
            java.lang.Object r3 = r1.getValue()
            r4 = r3
            com.quizlet.edgy.ui.viewmodel.s r4 = (com.quizlet.edgy.ui.viewmodel.s) r4
            com.quizlet.edgy.ui.viewmodel.h r4 = new com.quizlet.edgy.ui.viewmodel.h
            r4.<init>(r0, r7)
            boolean r1 = r1.k(r3, r4)
            if (r1 == 0) goto L3d
        L51:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.edgy.ui.viewmodel.G.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
