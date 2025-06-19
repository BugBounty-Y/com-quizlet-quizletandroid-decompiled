package com.google.android.gms.internal.mlkit_vision_camera;

/* loaded from: classes2.dex */
public abstract class k3 {
    /* JADX WARN: Removed duplicated region for block: B:15:0x002d  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0032  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x004a  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x004f  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0076  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0082  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x009e  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00a1  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00bd  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x0131  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x017d  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0181  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x01a2  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x020b  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0233  */
    /* JADX WARN: Removed duplicated region for block: B:89:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.ui.q r19, com.quizlet.studiablemodels.StudiableAudio r20, kotlin.jvm.functions.Function0 r21, kotlin.jvm.functions.Function1 r22, androidx.compose.runtime.InterfaceC0806l r23, int r24, int r25) {
        /*
            Method dump skipped, instructions count: 573
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.k3.a(androidx.compose.ui.q, com.quizlet.studiablemodels.StudiableAudio, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x002a  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0067  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.String g(java.lang.String r7) {
        /*
            java.lang.String r0 = "text"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r0)
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>()
            r1 = 0
            r2 = r1
        Lc:
            int r3 = r7.length()
            if (r2 >= r3) goto L71
            char r3 = r7.charAt(r2)
            r4 = 40
            if (r3 == r4) goto L67
            r4 = 41
            if (r3 == r4) goto L2a
            r4 = 12304(0x3010, float:1.7242E-41)
            if (r3 == r4) goto L67
            r4 = 12305(0x3011, float:1.7243E-41)
            if (r3 == r4) goto L2a
            switch(r3) {
                case 65288: goto L67;
                case 65289: goto L2a;
                default: goto L29;
            }
        L29:
            goto L6e
        L2a:
            int r3 = r0.size()
            if (r3 <= 0) goto L6e
            int r3 = r0.size()
            int r3 = r3 + (-1)
            java.lang.Object r3 = r0.remove(r3)
            java.lang.Number r3 = (java.lang.Number) r3
            int r3 = r3.intValue()
            java.lang.String r4 = r7.substring(r1, r3)
            java.lang.String r5 = "substring(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r5)
            int r6 = r2 + 1
            java.lang.String r7 = r7.substring(r6)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r5)
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            r5.<init>()
            r5.append(r4)
            r5.append(r7)
            java.lang.String r7 = r5.toString()
            int r3 = r2 - r3
            int r2 = r2 - r3
            int r2 = r2 + (-1)
            goto L6e
        L67:
            java.lang.Integer r3 = java.lang.Integer.valueOf(r2)
            r0.add(r3)
        L6e:
            int r2 = r2 + 1
            goto Lc
        L71:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.k3.g(java.lang.String):java.lang.String");
    }

    public abstract assistantMode.utils.classification.classifierTypes.a b();

    public abstract String c();

    public abstract assistantMode.utils.classification.classifierTypes.b d();

    public abstract String e();

    public abstract String f();
}
