package com.quizlet.features.notes.detail.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public boolean j;
    public int k;
    public final /* synthetic */ v l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(v vVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x004c  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.k
            r2 = 2
            com.quizlet.features.notes.detail.viewmodels.v r3 = r5.l
            r4 = 1
            if (r1 == 0) goto L20
            if (r1 == r4) goto L1c
            if (r1 != r2) goto L14
            boolean r0 = r5.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L41
        L14:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L2e
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.google.firebase.crashlytics.internal.settings.b r6 = r3.i
            r5.k = r4
            java.lang.Object r6 = r6.h(r5)
            if (r6 != r0) goto L2e
            goto L3e
        L2e:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            r5.j = r6
            r5.k = r2
            java.lang.Object r1 = r3.A(r5)
            if (r1 != r0) goto L3f
        L3e:
            return r0
        L3f:
            r0 = r6
            r6 = r1
        L41:
            com.quizlet.data.model.w0 r6 = (com.quizlet.data.model.InterfaceC4176w0) r6
            boolean r6 = r6.a0()
            if (r6 != 0) goto L4c
            if (r0 == 0) goto L4c
            goto L4d
        L4c:
            r4 = 0
        L4d:
            kotlinx.coroutines.flow.s0 r6 = r3.q
        L4f:
            java.lang.Object r0 = r6.getValue()
            r1 = r0
            com.quizlet.features.notes.detail.states.h r1 = (com.quizlet.features.notes.detail.states.h) r1
            com.quizlet.features.notes.detail.states.e r1 = new com.quizlet.features.notes.detail.states.e
            com.quizlet.features.notes.data.s r2 = new com.quizlet.features.notes.data.s
            r2.<init>(r4)
            r1.<init>(r2)
            boolean r0 = r6.k(r0, r1)
            if (r0 == 0) goto L4f
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.detail.viewmodels.i.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
