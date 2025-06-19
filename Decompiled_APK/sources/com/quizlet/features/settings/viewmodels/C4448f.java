package com.quizlet.features.settings.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.settings.viewmodels.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4448f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public int k;
    public final /* synthetic */ C4449g l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4448f(C4449g c4449g, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c4449g;
        this.m = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4448f(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4448f) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0070  */
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
            r2 = 2
            r3 = 1
            com.quizlet.features.settings.viewmodels.g r4 = r6.l
            if (r1 == 0) goto L24
            if (r1 == r3) goto L1c
            if (r1 != r2) goto L14
            java.lang.Object r0 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L69
        L14:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r7 = r7.a
            goto L36
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.data.repository.qclass.c r7 = r4.d
            r6.k = r3
            java.lang.String r1 = r6.m
            java.lang.String r3 = r4.g
            java.lang.Object r7 = r7.i(r3, r1, r6)
            if (r7 != r0) goto L36
            goto L67
        L36:
            kotlin.p r1 = kotlin.r.b
            boolean r1 = r7 instanceof kotlin.q
            if (r1 != 0) goto L6a
            r1 = r7
            kotlin.Unit r1 = (kotlin.Unit) r1
            kotlinx.coroutines.flow.s0 r1 = r4.f
        L41:
            java.lang.Object r3 = r1.getValue()
            r5 = r3
            com.quizlet.features.settings.data.states.l r5 = (com.quizlet.features.settings.data.states.l) r5
            com.quizlet.features.settings.data.states.j r5 = com.quizlet.features.settings.data.states.j.a
            boolean r3 = r1.k(r3, r5)
            if (r3 == 0) goto L41
            com.quizlet.features.emailconfirmation.logging.a r1 = r4.e
            com.quizlet.eventlogger.EventLogger r1 = r1.a
            java.lang.String r3 = "user_profile_change_username"
            r1.I(r3)
            kotlinx.coroutines.flow.d0 r1 = r4.b
            kotlin.Unit r3 = kotlin.Unit.a
            r6.j = r7
            r6.k = r2
            java.lang.Object r1 = r1.emit(r3, r6)
            if (r1 != r0) goto L68
        L67:
            return r0
        L68:
            r0 = r7
        L69:
            r7 = r0
        L6a:
            java.lang.Throwable r7 = kotlin.r.a(r7)
            if (r7 == 0) goto L7a
            com.quizlet.features.folders.composables.J r0 = new com.quizlet.features.folders.composables.J
            r1 = 16
            r0.<init>(r4, r1)
            r4.A(r0, r7)
        L7a:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.settings.viewmodels.C4448f.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
