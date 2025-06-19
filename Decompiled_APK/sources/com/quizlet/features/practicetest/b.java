package com.quizlet.features.practicetest;

import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class b implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ PracticeTestActivity b;

    public /* synthetic */ b(PracticeTestActivity practiceTestActivity, int i) {
        this.a = i;
        this.b = practiceTestActivity;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0023  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0057  */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r11, java.lang.Object r12) {
        /*
            r10 = this;
            com.quizlet.features.practicetest.PracticeTestActivity r0 = r10.b
            r1 = 2
            int r2 = r10.a
            switch(r2) {
                case 0: goto L3c;
                default: goto L8;
            }
        L8:
            r7 = r11
            androidx.compose.runtime.l r7 = (androidx.compose.runtime.InterfaceC0806l) r7
            java.lang.Number r12 = (java.lang.Number) r12
            int r11 = r12.intValue()
            r11 = r11 & 3
            if (r11 != r1) goto L23
            r11 = r7
            androidx.compose.runtime.p r11 = (androidx.compose.runtime.C0814p) r11
            boolean r12 = r11.x()
            if (r12 != 0) goto L1f
            goto L23
        L1f:
            r11.Q()
            goto L39
        L23:
            com.quizlet.features.practicetest.b r11 = new com.quizlet.features.practicetest.b
            r12 = 0
            r11.<init>(r0, r12)
            r12 = 1525385671(0x5aeb89c7, float:3.3149054E16)
            androidx.compose.runtime.internal.d r6 = androidx.compose.runtime.internal.e.e(r12, r11, r7)
            r8 = 3072(0xc00, float:4.305E-42)
            r9 = 7
            r3 = 0
            r4 = 0
            r5 = 0
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5.b(r3, r4, r5, r6, r7, r8, r9)
        L39:
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        L3c:
            r6 = r11
            androidx.compose.runtime.l r6 = (androidx.compose.runtime.InterfaceC0806l) r6
            java.lang.Number r12 = (java.lang.Number) r12
            int r11 = r12.intValue()
            r11 = r11 & 3
            if (r11 != r1) goto L57
            r11 = r6
            androidx.compose.runtime.p r11 = (androidx.compose.runtime.C0814p) r11
            boolean r12 = r11.x()
            if (r12 != 0) goto L53
            goto L57
        L53:
            r11.Q()
            goto L8d
        L57:
            int r11 = com.quizlet.features.practicetest.PracticeTestActivity.h
            android.content.Intent r11 = r0.getIntent()
            java.lang.String r12 = "questionBankUuid"
            java.lang.String r11 = r11.getStringExtra(r12)
            android.content.Intent r12 = r0.getIntent()
            java.lang.String r1 = "navigationRoute"
            java.lang.String r12 = r12.getStringExtra(r1)
            if (r12 != 0) goto L71
            java.lang.String r12 = "practiceTest"
        L71:
            r1 = r12
            android.content.Intent r12 = r0.getIntent()
            java.lang.String r2 = "navigationOrigin"
            java.lang.String r2 = r12.getStringExtra(r2)
            android.content.Intent r12 = r0.getIntent()
            java.lang.String r0 = "practiceTestId"
            java.lang.String r3 = r12.getStringExtra(r0)
            r5 = 0
            r7 = 0
            r4 = 0
            r0 = r11
            com.quizlet.features.practicetest.navigation.c.a(r0, r1, r2, r3, r4, r5, r6, r7)
        L8d:
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.b.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
