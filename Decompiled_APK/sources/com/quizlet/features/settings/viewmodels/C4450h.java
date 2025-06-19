package com.quizlet.features.settings.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.settings.viewmodels.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4450h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public int k;
    public final /* synthetic */ C4451i l;
    public final /* synthetic */ String m;
    public final /* synthetic */ String n;
    public final /* synthetic */ String o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4450h(C4451i c4451i, String str, String str2, String str3, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c4451i;
        this.m = str;
        this.n = str2;
        this.o = str3;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4450h(this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4450h) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0072  */
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
            com.quizlet.features.settings.viewmodels.i r4 = r6.l
            if (r1 == 0) goto L24
            if (r1 == r3) goto L1c
            if (r1 != r2) goto L14
            java.lang.Object r0 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L6b
        L14:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r7 = r7.a
            goto L38
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.data.repository.qclass.c r7 = r4.d
            r6.k = r3
            java.lang.String r1 = r6.n
            java.lang.String r3 = r6.o
            java.lang.String r5 = r6.m
            java.lang.Object r7 = r7.a(r5, r1, r3, r6)
            if (r7 != r0) goto L38
            goto L69
        L38:
            kotlin.p r1 = kotlin.r.b
            boolean r1 = r7 instanceof kotlin.q
            if (r1 != 0) goto L6c
            r1 = r7
            kotlin.Unit r1 = (kotlin.Unit) r1
            kotlinx.coroutines.flow.s0 r1 = r4.g
        L43:
            java.lang.Object r3 = r1.getValue()
            r5 = r3
            com.quizlet.features.settings.data.states.h r5 = (com.quizlet.features.settings.data.states.h) r5
            com.quizlet.features.settings.data.states.f r5 = com.quizlet.features.settings.data.states.f.a
            boolean r3 = r1.k(r3, r5)
            if (r3 == 0) goto L43
            com.quizlet.features.emailconfirmation.logging.a r1 = r4.f
            com.quizlet.eventlogger.EventLogger r1 = r1.a
            java.lang.String r3 = "user_profile_add_password"
            r1.I(r3)
            kotlinx.coroutines.flow.d0 r1 = r4.b
            kotlin.Unit r3 = kotlin.Unit.a
            r6.j = r7
            r6.k = r2
            java.lang.Object r1 = r1.emit(r3, r6)
            if (r1 != r0) goto L6a
        L69:
            return r0
        L6a:
            r0 = r7
        L6b:
            r7 = r0
        L6c:
            java.lang.Throwable r7 = kotlin.r.a(r7)
            if (r7 == 0) goto L7c
            com.quizlet.features.folders.composables.J r0 = new com.quizlet.features.folders.composables.J
            r1 = 17
            r0.<init>(r4, r1)
            r4.A(r0, r7)
        L7c:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.settings.viewmodels.C4450h.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
