package com.quizlet.features.notes.detail.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ String k;
    public final /* synthetic */ v l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(v vVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new o(this.l, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((o) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0036, code lost:
    
        if (r5.G(r7, r6) == r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0045, code lost:
    
        if (r5.G(r7, r6) == r0) goto L17;
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
            r2 = 2
            java.lang.String r3 = r6.k
            r4 = 1
            com.quizlet.features.notes.detail.viewmodels.v r5 = r6.l
            if (r1 == 0) goto L20
            if (r1 == r4) goto L1c
            if (r1 != r2) goto L14
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L48
        L14:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L57
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            int r7 = r3.length()
            if (r7 != 0) goto L39
            com.quizlet.features.notes.data.c r7 = new com.quizlet.features.notes.data.c
            com.quizlet.features.notes.data.b r1 = com.quizlet.features.notes.data.b.a
            r7.<init>(r2)
            r6.j = r4
            java.lang.Object r7 = r5.G(r7, r6)
            if (r7 != r0) goto L57
            goto L47
        L39:
            com.quizlet.features.notes.data.c r7 = new com.quizlet.features.notes.data.c
            r1 = 4
            r7.<init>(r1)
            r6.j = r2
            java.lang.Object r7 = r5.G(r7, r6)
            if (r7 != r0) goto L48
        L47:
            return r0
        L48:
            androidx.lifecycle.viewmodel.internal.a r7 = androidx.lifecycle.p0.j(r5)
            com.quizlet.features.notes.detail.viewmodels.n r0 = new com.quizlet.features.notes.detail.viewmodels.n
            r1 = 0
            r0.<init>(r5, r3, r1)
            com.quizlet.features.notes.detail.viewmodels.t r3 = r5.w
            kotlinx.coroutines.E.A(r7, r3, r1, r0, r2)
        L57:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.detail.viewmodels.o.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
