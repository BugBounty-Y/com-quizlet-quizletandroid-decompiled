package com.quizlet.upgrade.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ n k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(n nVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new m(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x006b, code lost:
    
        if (r6.b(r1, r5) == r0) goto L18;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) throws java.lang.Throwable {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.j
            r2 = 2
            r3 = 1
            com.quizlet.upgrade.viewmodel.n r4 = r5.k
            if (r1 == 0) goto L1e
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L6e
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L3e
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.d r6 = r4.d
            r5.j = r3
            r6.getClass()
            com.quizlet.upgrade.manager.e r1 = new com.quizlet.upgrade.manager.e
            r3 = 0
            r1.<init>(r6, r3)
            java.lang.Object r6 = r6.d
            kotlinx.coroutines.scheduling.e r6 = (kotlinx.coroutines.scheduling.e) r6
            java.lang.Object r6 = kotlinx.coroutines.E.J(r6, r1, r5)
            if (r6 != r0) goto L39
            goto L3b
        L39:
            kotlin.Unit r6 = kotlin.Unit.a
        L3b:
            if (r6 != r0) goto L3e
            goto L6d
        L3e:
            com.lyft.android.scissors.b r6 = r4.c
            java.lang.Object r6 = r6.b
            com.quizlet.infra.legacysyncengine.managers.d r6 = (com.quizlet.infra.legacysyncengine.managers.d) r6
            io.reactivex.rxjava3.subjects.d r6 = r6.l
            r6.getClass()
            io.reactivex.rxjava3.internal.operators.observable.f r1 = new io.reactivex.rxjava3.internal.operators.observable.f
            r3 = 1
            r1.<init>(r6, r3)
            com.quizlet.billing.manager.user.a r6 = com.quizlet.billing.manager.user.a.a
            io.reactivex.rxjava3.internal.operators.observable.J r6 = r1.q(r6)
            java.lang.String r1 = "map(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r1)
            kotlinx.coroutines.flow.c r6 = com.google.android.gms.internal.mlkit_vision_camera.K1.f(r6)
            androidx.compose.foundation.text.input.internal.b r1 = new androidx.compose.foundation.text.input.internal.b
            r3 = 23
            r1.<init>(r4, r3)
            r5.j = r2
            java.lang.Object r6 = r6.b(r1, r5)
            if (r6 != r0) goto L6e
        L6d:
            return r0
        L6e:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.upgrade.viewmodel.m.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
