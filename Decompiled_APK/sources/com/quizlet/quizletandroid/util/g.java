package com.quizlet.quizletandroid.util;

/* loaded from: classes3.dex */
public final class g {
    /* JADX WARN: Removed duplicated region for block: B:16:0x004f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void a(android.app.Activity r4, com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute.CreateSet r5) {
        /*
            java.lang.String r0 = "activity"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            android.content.Intent r0 = r4.getIntent()
            java.lang.String r0 = r0.getAction()
            if (r0 == 0) goto L4f
            int r1 = r0.hashCode()
            r2 = 531603730(0x1fafa112, float:7.438185E-20)
            r3 = 268468224(0x10008000, float:2.5342157E-29)
            if (r1 == r2) goto L32
            r2 = 1525799137(0x5af1d8e1, float:3.4036965E16)
            if (r1 == r2) goto L21
            goto L4f
        L21:
            java.lang.String r1 = "open_start_activity"
            boolean r0 = r0.equals(r1)
            if (r0 != 0) goto L2a
            goto L4f
        L2a:
            android.content.Intent r5 = com.google.android.gms.internal.mlkit_vision_document_scanner.D4.a(r4, r5)
            r5.addFlags(r3)
            goto L50
        L32:
            java.lang.String r1 = "require_email_confirmation"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L4f
            java.lang.String r0 = com.quizlet.features.emailconfirmation.ui.activities.EmailConfirmationActivity.r
            android.content.Intent r5 = com.google.android.gms.internal.mlkit_vision_document_scanner.D4.a(r4, r5)
            r5.addFlags(r3)
            android.content.Intent[] r5 = new android.content.Intent[]{r5}
            android.content.Intent r5 = com.google.android.gms.internal.mlkit_vision_barcode.T.b(r4, r5)
            r5.addFlags(r3)
            goto L50
        L4f:
            r5 = 0
        L50:
            if (r5 == 0) goto L55
            r4.startActivity(r5)
        L55:
            r4.finish()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.util.g.a(android.app.Activity, com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute$CreateSet):void");
    }
}
