package com.quizlet.features.onboarding.ell;

import com.google.android.gms.measurement.internal.J;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class p extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ boolean k;
    public final /* synthetic */ J l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(boolean z, J j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = z;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new p(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((p) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x0094, code lost:
    
        if (r10 == r0) goto L23;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.j
            r2 = 0
            java.lang.String r3 = "format(...)"
            com.google.android.gms.measurement.internal.J r4 = r9.l
            r5 = 2
            r6 = 1
            if (r1 == 0) goto L22
            if (r1 == r6) goto L1e
            if (r1 != r5) goto L16
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L97
        L16:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L60
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            boolean r10 = r9.k
            if (r10 == 0) goto L60
            java.lang.Object r10 = r4.e
            com.lyft.android.scissors.b r10 = (com.lyft.android.scissors.b) r10
            r9.j = r6
            java.lang.Long r1 = new java.lang.Long
            long r7 = r4.b
            r1.<init>(r7)
            java.lang.Object[] r1 = new java.lang.Object[]{r1}
            java.lang.Object[] r1 = java.util.Arrays.copyOf(r1, r6)
            java.lang.String r7 = "user_is_studying_english_%s"
            java.lang.String r1 = java.lang.String.format(r7, r1)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r3)
            androidx.datastore.preferences.core.f r1 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r1)
            com.quizlet.local.datastore.preferences.b0 r7 = new com.quizlet.local.datastore.preferences.b0
            r7.<init>(r1, r2)
            java.lang.Object r10 = r10.b
            androidx.datastore.core.h r10 = (androidx.datastore.core.InterfaceC1076h) r10
            java.lang.Object r10 = com.google.android.gms.internal.mlkit_vision_barcode.S6.d(r10, r7, r9)
            if (r10 != r0) goto L5b
            goto L5d
        L5b:
            kotlin.Unit r10 = kotlin.Unit.a
        L5d:
            if (r10 != r0) goto L60
            goto L96
        L60:
            java.lang.Object r10 = r4.e
            com.lyft.android.scissors.b r10 = (com.lyft.android.scissors.b) r10
            r9.j = r5
            java.lang.Long r1 = new java.lang.Long
            long r4 = r4.b
            r1.<init>(r4)
            java.lang.Object[] r1 = new java.lang.Object[]{r1}
            java.lang.Object[] r1 = java.util.Arrays.copyOf(r1, r6)
            java.lang.String r4 = "user_completed_onboarding_ell_%s"
            java.lang.String r1 = java.lang.String.format(r4, r1)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r3)
            androidx.datastore.preferences.core.f r1 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r1)
            com.quizlet.local.datastore.preferences.a0 r3 = new com.quizlet.local.datastore.preferences.a0
            r3.<init>(r1, r2)
            java.lang.Object r10 = r10.b
            androidx.datastore.core.h r10 = (androidx.datastore.core.InterfaceC1076h) r10
            java.lang.Object r10 = com.google.android.gms.internal.mlkit_vision_barcode.S6.d(r10, r3, r9)
            if (r10 != r0) goto L92
            goto L94
        L92:
            kotlin.Unit r10 = kotlin.Unit.a
        L94:
            if (r10 != r0) goto L97
        L96:
            return r0
        L97:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.onboarding.ell.p.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
