package com.quizlet.edgy.ui.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class I extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ M k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(M m, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = m;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new I(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((I) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0038, code lost:
    
        if (r7 == r0) goto L15;
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
            com.quizlet.edgy.ui.viewmodel.M r2 = r6.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L3b
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
            goto L3a
        L2c:
            r6.j = r3
            java.lang.String r7 = r6.l
            r1 = 20
            com.onetrust.otpublishers.headless.UI.fragment.q r3 = r2.b
            java.lang.Object r7 = r3.m(r7, r1, r6)
            if (r7 != r0) goto L3b
        L3a:
            return r0
        L3b:
            com.quizlet.data.model.x1 r7 = (com.quizlet.data.model.C4180x1) r7
            java.util.List r7 = r7.a
            java.util.ArrayList r0 = new java.util.ArrayList
            r1 = 10
            int r1 = kotlin.collections.C.q(r7, r1)
            r0.<init>(r1)
            java.util.Iterator r7 = r7.iterator()
        L4e:
            boolean r1 = r7.hasNext()
            if (r1 == 0) goto L62
            java.lang.Object r1 = r7.next()
            com.quizlet.data.model.School r1 = (com.quizlet.data.model.School) r1
            com.quizlet.edgy.ui.recyclerview.adapter.i r1 = com.google.android.gms.internal.mlkit_vision_document_scanner.P6.a(r1)
            r0.add(r1)
            goto L4e
        L62:
            kotlinx.coroutines.flow.s0 r7 = r2.p
            java.lang.Object r1 = r7.getValue()
            r3 = r1
            com.quizlet.edgy.ui.viewmodel.s r3 = (com.quizlet.edgy.ui.viewmodel.s) r3
            com.quizlet.edgy.ui.viewmodel.p r3 = new com.quizlet.edgy.ui.viewmodel.p
            r3.<init>(r0)
            boolean r7 = r7.k(r1, r3)
            if (r7 == 0) goto L62
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.edgy.ui.viewmodel.I.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
