package com.quizlet.features.setpage.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class K extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ P k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new K(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0047, code lost:
    
        if (com.quizlet.features.setpage.viewmodel.P.B(r2, r8, r7) == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) throws java.lang.Throwable {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            com.quizlet.features.setpage.viewmodel.P r2 = r7.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4a
        L12:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L3b
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y r8 = r2.H
            long r5 = r2.D()
            r7.j = r4
            r8.getClass()
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.u r1 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.u
            r4 = 0
            r1.<init>(r8, r5, r4)
            kotlinx.coroutines.y r8 = r8.e
            java.lang.Object r8 = kotlinx.coroutines.E.J(r8, r1, r7)
            if (r8 != r0) goto L3b
            goto L49
        L3b:
            com.quizlet.data.model.w0 r8 = (com.quizlet.data.model.InterfaceC4176w0) r8
            com.quizlet.features.infra.basestudy.data.models.MeteredValue r8 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3241q5.e(r8)
            r7.j = r3
            java.lang.Object r8 = com.quizlet.features.setpage.viewmodel.P.B(r2, r8, r7)
            if (r8 != r0) goto L4a
        L49:
            return r0
        L4a:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.viewmodel.K.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
