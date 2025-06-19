package com.quizlet.login;

import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ LoginNavActivity b;

    public /* synthetic */ a(LoginNavActivity loginNavActivity, int i) {
        this.a = i;
        this.b = loginNavActivity;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0024  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0057  */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r12, java.lang.Object r13) {
        /*
            r11 = this;
            r0 = 0
            com.quizlet.login.LoginNavActivity r1 = r11.b
            r2 = 2
            int r3 = r11.a
            switch(r3) {
                case 0: goto L3c;
                default: goto L9;
            }
        L9:
            r8 = r12
            androidx.compose.runtime.l r8 = (androidx.compose.runtime.InterfaceC0806l) r8
            java.lang.Number r13 = (java.lang.Number) r13
            int r12 = r13.intValue()
            r12 = r12 & 3
            if (r12 != r2) goto L24
            r12 = r8
            androidx.compose.runtime.p r12 = (androidx.compose.runtime.C0814p) r12
            boolean r13 = r12.x()
            if (r13 != 0) goto L20
            goto L24
        L20:
            r12.Q()
            goto L39
        L24:
            com.quizlet.login.a r12 = new com.quizlet.login.a
            r12.<init>(r1, r0)
            r13 = 1971216578(0x757e60c2, float:3.2246237E32)
            androidx.compose.runtime.internal.d r7 = androidx.compose.runtime.internal.e.e(r13, r12, r8)
            r9 = 3072(0xc00, float:4.305E-42)
            r10 = 7
            r4 = 0
            r5 = 0
            r6 = 0
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5.b(r4, r5, r6, r7, r8, r9, r10)
        L39:
            kotlin.Unit r12 = kotlin.Unit.a
            return r12
        L3c:
            r7 = r12
            androidx.compose.runtime.l r7 = (androidx.compose.runtime.InterfaceC0806l) r7
            java.lang.Number r13 = (java.lang.Number) r13
            int r12 = r13.intValue()
            r12 = r12 & 3
            if (r12 != r2) goto L57
            r12 = r7
            androidx.compose.runtime.p r12 = (androidx.compose.runtime.C0814p) r12
            boolean r13 = r12.x()
            if (r13 != 0) goto L53
            goto L57
        L53:
            r12.Q()
            goto L95
        L57:
            java.lang.String r12 = com.quizlet.login.LoginNavActivity.i
            android.content.Intent r12 = r1.getIntent()
            java.lang.String r13 = "shouldKillApp"
            boolean r2 = r12.getBooleanExtra(r13, r0)
            android.content.Intent r12 = r1.getIntent()
            java.lang.String r13 = "shouldSkipUpsell"
            boolean r3 = r12.getBooleanExtra(r13, r0)
            android.content.Intent r12 = r1.getIntent()
            java.lang.String r13 = "magicLinkCode"
            java.lang.String r4 = r12.getStringExtra(r13)
            android.content.Intent r0 = r1.getIntent()
            java.lang.String r12 = "getIntent(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r12)
            android.content.Intent r12 = r1.getIntent()
            java.lang.String r13 = "navigationRoute"
            java.lang.String r12 = r12.getStringExtra(r13)
            if (r12 != 0) goto L8e
            java.lang.String r12 = "intro"
        L8e:
            r1 = r12
            r6 = 0
            r8 = 0
            r5 = 0
            com.quizlet.login.common.navigation.e.b(r0, r1, r2, r3, r4, r5, r6, r7, r8)
        L95:
            kotlin.Unit r12 = kotlin.Unit.a
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.a.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
