package com.quizlet.upgrade.upsell.viewmodel;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public s0 j;
    public int k;
    public final /* synthetic */ c l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(c cVar, h hVar) {
        super(2, hVar);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0048, code lost:
    
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
            goto L4b
        L10:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L18:
            kotlinx.coroutines.flow.s0 r1 = r4.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L33
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            com.quizlet.upgrade.upsell.viewmodel.c r5 = r4.l
            kotlinx.coroutines.flow.s0 r1 = r5.c
            r4.j = r1
            r4.k = r3
            r3 = 0
            androidx.work.impl.model.e r5 = r5.b
            java.lang.Object r5 = r5.s(r3, r4)
            if (r5 != r0) goto L33
            goto L4a
        L33:
            com.quizlet.data.model.u2 r5 = (com.quizlet.data.model.u2) r5
            boolean r5 = r5.b
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            r3 = 0
            r4.j = r3
            r4.k = r2
            r1.getClass()
            r1.m(r3, r5)
            kotlin.Unit r5 = kotlin.Unit.a
            if (r5 != r0) goto L4b
        L4a:
            return r0
        L4b:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.upgrade.upsell.viewmodel.a.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
