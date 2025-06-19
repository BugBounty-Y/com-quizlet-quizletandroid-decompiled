package com.quizlet.features.infra.folder.save.viewmodel;

import com.quizlet.generated.enums.y1;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;
    public final /* synthetic */ String l;
    public final /* synthetic */ y1 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, y1 y1Var, String str, h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = str;
        this.m = y1Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        String str = this.l;
        return new b(this.k, this.m, str, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0050  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.j
            com.quizlet.features.infra.folder.save.viewmodel.c r2 = r5.k
            r3 = 1
            if (r1 == 0) goto L1b
            if (r1 != r3) goto L13
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.r r6 = (kotlin.r) r6
            java.lang.Object r6 = r6.a
            goto L2d
        L13:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.compose.foundation.gestures.l1 r6 = r2.b
            r5.j = r3
            java.lang.String r1 = r5.l
            com.quizlet.generated.enums.y1 r4 = r5.m
            java.lang.Object r6 = r6.D(r1, r4, r5)
            if (r6 != r0) goto L2d
            return r0
        L2d:
            java.lang.Throwable r0 = kotlin.r.a(r6)
            if (r0 == 0) goto L3c
            boolean r0 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3746v6.b(r0)
            if (r0 != r3) goto L3c
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L3c:
            boolean r0 = r6 instanceof kotlin.q
            if (r0 != 0) goto L50
            java.lang.Boolean r1 = java.lang.Boolean.FALSE
            if (r0 == 0) goto L45
            r6 = r1
        L45:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 == 0) goto L50
            com.quizlet.features.infra.folder.save.screenstates.a r6 = com.quizlet.features.infra.folder.save.screenstates.a.a
            goto L52
        L50:
            com.quizlet.features.infra.folder.save.screenstates.a r6 = com.quizlet.features.infra.folder.save.screenstates.a.b
        L52:
            kotlinx.coroutines.flow.s0 r0 = r2.f
        L54:
            java.lang.Object r1 = r0.getValue()
            r2 = r1
            com.quizlet.features.infra.folder.save.screenstates.d r2 = (com.quizlet.features.infra.folder.save.screenstates.d) r2
            com.quizlet.features.infra.folder.save.screenstates.c r2 = new com.quizlet.features.infra.folder.save.screenstates.c
            r2.<init>(r6)
            boolean r1 = r0.k(r1, r2)
            if (r1 == 0) goto L54
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.save.viewmodel.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
