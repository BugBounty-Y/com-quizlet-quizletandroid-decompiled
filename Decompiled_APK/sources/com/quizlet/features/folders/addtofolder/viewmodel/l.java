package com.quizlet.features.folders.addtofolder.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ m k;
    public final /* synthetic */ com.quizlet.features.folders.addtofolder.data.n l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(m mVar, com.quizlet.features.folders.addtofolder.data.n nVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = mVar;
        this.l = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new l(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x006a, code lost:
    
        if (com.quizlet.features.folders.addtofolder.viewmodel.m.B(r2, r4, r7) != r0) goto L28;
     */
    /* JADX WARN: Removed duplicated region for block: B:25:0x005e  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            com.quizlet.features.folders.addtofolder.viewmodel.m r2 = r7.k
            r3 = 4
            r4 = 3
            r5 = 2
            r6 = 1
            if (r1 == 0) goto L2c
            if (r1 == r6) goto L28
            if (r1 == r5) goto L24
            if (r1 == r4) goto L20
            if (r1 != r3) goto L18
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L6d
        L18:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L5e
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4b
        L28:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L3a
        L2c:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r7.j = r6
            com.quizlet.data.repository.user.a r8 = r2.h
            java.lang.Object r8 = r8.j(r7)
            if (r8 != r0) goto L3a
            goto L6c
        L3a:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            if (r8 == 0) goto L4b
            r7.j = r5
            java.lang.Object r8 = com.quizlet.features.folders.addtofolder.viewmodel.m.D(r2, r7)
            if (r8 != r0) goto L4b
            goto L6c
        L4b:
            kotlinx.coroutines.flow.s0 r8 = r2.j
            java.lang.Object r8 = r8.getValue()
            com.quizlet.features.folders.addtofolder.data.u r8 = (com.quizlet.features.folders.addtofolder.data.u) r8
            com.quizlet.features.folders.addtofolder.data.o r8 = r8.b
            r7.j = r4
            java.lang.Object r8 = com.quizlet.features.folders.addtofolder.viewmodel.m.C(r2, r8, r7)
            if (r8 != r0) goto L5e
            goto L6c
        L5e:
            com.quizlet.features.folders.addtofolder.data.n r8 = r7.l
            com.quizlet.features.folders.addtofolder.data.e r8 = (com.quizlet.features.folders.addtofolder.data.e) r8
            long r4 = r8.b
            r7.j = r3
            java.lang.Object r8 = com.quizlet.features.folders.addtofolder.viewmodel.m.B(r2, r4, r7)
            if (r8 != r0) goto L6d
        L6c:
            return r0
        L6d:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.addtofolder.viewmodel.l.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
