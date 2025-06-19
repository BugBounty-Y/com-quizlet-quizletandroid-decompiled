package com.quizlet.features.infra.folder.menu.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public s0 j;
    public m k;
    public Object l;
    public int m;
    public final /* synthetic */ m n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /*  JADX ERROR: JadxOverflowException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxOverflowException: Regions count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        */
    /* JADX WARN: Removed duplicated region for block: B:11:0x003e A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:14:0x004a  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:10:0x003c -> B:12:0x003f). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.m
            r2 = 1
            if (r1 == 0) goto L1b
            if (r1 != r2) goto L13
            java.lang.Object r1 = r5.l
            com.quizlet.features.infra.folder.menu.viewmodel.m r3 = r5.k
            kotlinx.coroutines.flow.s0 r4 = r5.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L3f
        L13:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.features.infra.folder.menu.viewmodel.m r6 = r5.n
            kotlinx.coroutines.flow.s0 r1 = r6.k
            r3 = r6
            r4 = r1
        L24:
            java.lang.Object r1 = r4.getValue()
            r6 = r1
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            r6.getClass()
            com.quizlet.data.repository.user.a r6 = r3.d
            r5.j = r4
            r5.k = r3
            r5.l = r1
            r5.m = r2
            java.lang.Object r6 = r6.j(r5)
            if (r6 != r0) goto L3f
            return r0
        L3f:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            r6.getClass()
            boolean r6 = r4.k(r1, r6)
            if (r6 == 0) goto L24
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.menu.viewmodel.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
