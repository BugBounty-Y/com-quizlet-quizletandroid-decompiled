package com.quizlet.features.folders.viewmodel;

import com.quizlet.features.folders.data.P0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class H extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        H h = new H(2, hVar);
        h.j = obj;
        return h;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((H) create((P0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0038  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r5) {
        /*
            r4 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            androidx.glance.appwidget.protobuf.Z.e(r5)
            java.lang.Object r5 = r4.j
            com.quizlet.features.folders.data.P0 r5 = (com.quizlet.features.folders.data.P0) r5
            boolean r0 = r5 instanceof com.quizlet.features.folders.data.L0
            if (r0 == 0) goto L38
            com.quizlet.features.folders.data.L0 r5 = (com.quizlet.features.folders.data.L0) r5
            kotlinx.collections.immutable.b r0 = r5.a
            java.util.ArrayList r1 = new java.util.ArrayList
            r1.<init>()
            java.util.Iterator r0 = r0.iterator()
        L1a:
            boolean r2 = r0.hasNext()
            if (r2 == 0) goto L2c
            java.lang.Object r2 = r0.next()
            boolean r3 = r2 instanceof com.quizlet.ui.models.content.listitem.l
            if (r3 == 0) goto L1a
            r1.add(r2)
            goto L1a
        L2c:
            boolean r0 = r1.isEmpty()
            if (r0 != 0) goto L38
            java.lang.String r5 = r5.c
            if (r5 != 0) goto L38
            r5 = 1
            goto L39
        L38:
            r5 = 0
        L39:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.H.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
