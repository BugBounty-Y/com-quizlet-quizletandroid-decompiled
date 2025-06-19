package com.quizlet.features.home.viewmodel;

import com.quizlet.data.model.v2;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public v2 j;
    public int k;
    public final /* synthetic */ c l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, h hVar) {
        super(2, hVar);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x006c  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) throws java.lang.Throwable {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.k
            r2 = 3
            r3 = 2
            r4 = 1
            com.quizlet.features.home.viewmodel.c r5 = r6.l
            if (r1 == 0) goto L2a
            if (r1 == r4) goto L26
            if (r1 == r3) goto L1f
            if (r1 != r2) goto L17
            com.quizlet.data.model.v2 r0 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L6e
        L17:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1f:
            com.quizlet.data.model.v2 r1 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r7 = r1
            goto L5f
        L26:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L38
        L2a:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.data.repository.classmembership.c r7 = r5.b
            r6.k = r4
            java.lang.Object r7 = r7.d(r6)
            if (r7 != r0) goto L38
            goto L6b
        L38:
            com.quizlet.data.model.v2 r7 = (com.quizlet.data.model.v2) r7
            com.lyft.android.scissors.b r1 = r5.c
            r6.j = r7
            r6.k = r3
            java.lang.Object r1 = r1.b
            com.quizlet.data.repository.activitycenter.b r1 = (com.quizlet.data.repository.activitycenter.b) r1
            com.quizlet.remote.model.feed.a r3 = new com.quizlet.remote.model.feed.a
            r4 = 0
            r3.<init>(r1, r4)
            java.lang.Object r1 = r1.b
            kotlinx.coroutines.y r1 = (kotlinx.coroutines.AbstractC5040y) r1
            java.lang.Object r1 = kotlinx.coroutines.E.J(r1, r3, r6)
            if (r1 != r0) goto L55
            goto L57
        L55:
            kotlin.Unit r1 = kotlin.Unit.a
        L57:
            if (r1 != r0) goto L5a
            goto L5c
        L5a:
            kotlin.Unit r1 = kotlin.Unit.a
        L5c:
            if (r1 != r0) goto L5f
            goto L6b
        L5f:
            com.quizlet.data.repository.user.a r1 = r5.e
            r6.j = r7
            r6.k = r2
            java.lang.Object r1 = r1.j(r6)
            if (r1 != r0) goto L6c
        L6b:
            return r0
        L6c:
            r0 = r7
            r7 = r1
        L6e:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            kotlinx.coroutines.flow.s0 r1 = r5.f
        L76:
            java.lang.Object r2 = r1.getValue()
            r3 = r2
            com.quizlet.features.home.data.u r3 = (com.quizlet.features.home.data.u) r3
            com.quizlet.features.home.data.s r3 = new com.quizlet.features.home.data.s
            r3.<init>(r0, r7)
            boolean r2 = r1.k(r2, r3)
            if (r2 == 0) goto L76
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.home.viewmodel.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
