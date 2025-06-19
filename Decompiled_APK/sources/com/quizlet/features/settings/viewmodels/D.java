package com.quizlet.features.settings.viewmodels;

import com.quizlet.data.model.C4135i0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class D extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C4135i0 k;
    public final /* synthetic */ I l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(C4135i0 c4135i0, I i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c4135i0;
        this.l = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new D(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((D) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0039  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0046  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0058  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x005b  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0060  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0070  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r23) {
        /*
            r22 = this;
            r0 = r22
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.j
            r3 = 1
            if (r2 == 0) goto L18
            if (r2 != r3) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r23)
            goto Lbf
        L10:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L18:
            androidx.glance.appwidget.protobuf.Z.e(r23)
            com.quizlet.data.model.i0 r2 = r0.k
            boolean r4 = r2.I
            com.quizlet.features.settings.viewmodels.I r5 = r0.l
            if (r4 == 0) goto Lb4
            r5.getClass()
            int r1 = r2.e
            r2 = 2
            if (r1 == r3) goto L39
            if (r1 == r2) goto L35
            r4 = 3
            if (r1 == r4) goto L39
            r1 = 2132018247(0x7f140447, float:1.9674795E38)
        L33:
            r4 = r1
            goto L3d
        L35:
            r1 = 2132019414(0x7f1408d6, float:1.9677162E38)
            goto L33
        L39:
            r1 = 2132019409(0x7f1408d1, float:1.9677152E38)
            goto L33
        L3d:
            com.quizlet.billing.model.a r1 = r5.c
            com.android.billingclient.api.Purchase r6 = r1.b()
            r7 = 0
            if (r6 == 0) goto L58
            java.lang.String r6 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3722s6.d(r6)
            java.lang.String r8 = "sku"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r8)
            java.util.LinkedHashMap r1 = r1.a
            java.lang.Object r1 = r1.get(r6)
            com.quizlet.data.model.billing.a r1 = (com.quizlet.data.model.billing.a) r1
            goto L59
        L58:
            r1 = r7
        L59:
            if (r1 == 0) goto L60
            com.quizlet.data.model.billing.b r1 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3778z6.b(r1)
            goto L61
        L60:
            r1 = r7
        L61:
            r6 = -1
            if (r1 != 0) goto L66
            r1 = r6
            goto L6e
        L66:
            int[] r8 = com.quizlet.features.settings.viewmodels.v.a
            int r1 = r1.ordinal()
            r1 = r8[r1]
        L6e:
            if (r1 == r6) goto L89
            if (r1 == r3) goto L82
            if (r1 != r2) goto L7c
            r1 = 2132017277(0x7f14007d, float:1.9672828E38)
            java.lang.Integer r7 = java.lang.Integer.valueOf(r1)
            goto L89
        L7c:
            kotlin.NoWhenBranchMatchedException r1 = new kotlin.NoWhenBranchMatchedException
            r1.<init>()
            throw r1
        L82:
            r1 = 2132018908(0x7f1406dc, float:1.9676136E38)
            java.lang.Integer r7 = java.lang.Integer.valueOf(r1)
        L89:
            kotlinx.coroutines.flow.s0 r1 = r5.n
            java.lang.Object r2 = r1.getValue()
            r8 = r2
            com.quizlet.features.settings.data.states.y r8 = (com.quizlet.features.settings.data.states.y) r8
            com.quizlet.features.settings.data.models.j r14 = new com.quizlet.features.settings.data.models.j
            r14.<init>(r4, r7)
            r19 = 0
            r20 = 0
            r9 = 0
            r10 = 0
            r11 = 0
            r12 = 0
            r13 = 0
            r15 = 0
            r16 = 0
            r17 = 0
            r18 = 0
            r21 = 8159(0x1fdf, float:1.1433E-41)
            com.quizlet.features.settings.data.states.y r3 = com.quizlet.features.settings.data.states.y.a(r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21)
            boolean r1 = r1.k(r2, r3)
            if (r1 == 0) goto L89
            goto Lbf
        Lb4:
            r0.j = r3
            int r2 = r2.o
            java.lang.Object r2 = com.quizlet.features.settings.viewmodels.I.B(r5, r2, r0)
            if (r2 != r1) goto Lbf
            return r1
        Lbf:
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.settings.viewmodels.D.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
