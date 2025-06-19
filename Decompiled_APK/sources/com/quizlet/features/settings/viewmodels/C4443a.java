package com.quizlet.features.settings.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.settings.viewmodels.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4443a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public C4444b k;
    public int l;
    public final /* synthetic */ C4444b m;
    public final /* synthetic */ String n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4443a(C4444b c4444b, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = c4444b;
        this.n = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4443a(this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4443a) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x007b  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) throws java.lang.Throwable {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.l
            r2 = 2
            r3 = 1
            com.quizlet.features.settings.viewmodels.b r4 = r6.m
            if (r1 == 0) goto L27
            if (r1 == r3) goto L1e
            if (r1 != r2) goto L16
            com.quizlet.features.settings.viewmodels.b r0 = r6.k
            java.lang.Object r1 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L6e
        L16:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r7 = r7.a
        L25:
            r1 = r7
            goto L39
        L27:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.data.repository.qclass.c r7 = r4.d
            r6.l = r3
            java.lang.String r1 = r6.n
            java.lang.String r3 = r4.g
            java.lang.Object r7 = r7.f(r3, r1, r6)
            if (r7 != r0) goto L25
            goto L6c
        L39:
            kotlin.p r7 = kotlin.r.b
            boolean r7 = r1 instanceof kotlin.q
            if (r7 != 0) goto L75
            r7 = r1
            kotlin.Unit r7 = (kotlin.Unit) r7
            kotlinx.coroutines.flow.s0 r7 = r4.f
        L44:
            java.lang.Object r3 = r7.getValue()
            r5 = r3
            com.quizlet.features.settings.data.states.d r5 = (com.quizlet.features.settings.data.states.d) r5
            com.quizlet.features.settings.data.states.b r5 = com.quizlet.features.settings.data.states.b.a
            boolean r3 = r7.k(r3, r5)
            if (r3 == 0) goto L44
            com.quizlet.features.emailconfirmation.logging.a r7 = r4.e
            com.quizlet.eventlogger.EventLogger r7 = r7.a
            java.lang.String r3 = "user_profile_change_email"
            r7.I(r3)
            kotlinx.coroutines.flow.d0 r7 = r4.b
            kotlin.Unit r3 = kotlin.Unit.a
            r6.j = r1
            r6.k = r4
            r6.l = r2
            java.lang.Object r7 = r7.emit(r3, r6)
            if (r7 != r0) goto L6d
        L6c:
            return r0
        L6d:
            r0 = r4
        L6e:
            kotlinx.coroutines.flow.d0 r7 = r0.h
            kotlin.Unit r0 = kotlin.Unit.a
            r7.h(r0)
        L75:
            java.lang.Throwable r7 = kotlin.r.a(r1)
            if (r7 == 0) goto L85
            com.quizlet.features.folders.composables.J r0 = new com.quizlet.features.folders.composables.J
            r1 = 15
            r0.<init>(r4, r1)
            r4.A(r0, r7)
        L85:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.settings.viewmodels.C4443a.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
