package com.onetrust.otpublishers.headless.UI.UIProperty;

import android.content.Context;
import androidx.annotation.NonNull;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.cloudmessaging.k;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3625g4;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class d {
    public final int a;
    public final JSONObject b;
    public final Context c;

    public d(@NonNull Context context) {
        this.c = context;
        this.b = new com.onetrust.otpublishers.headless.Internal.Preferences.e(context).e();
        this.a = 22;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x003b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.camera.camera2.internal.c0 a(org.json.JSONObject r6, int r7) {
        /*
            androidx.camera.camera2.internal.c0 r0 = new androidx.camera.camera2.internal.c0
            r1 = 13
            r0.<init>(r1)
            java.lang.String r1 = "show"
            boolean r2 = r6.has(r1)
            if (r2 == 0) goto L15
            java.lang.String r1 = r6.getString(r1)
            r0.e = r1
        L15:
            java.lang.String r1 = "showText"
            boolean r2 = r6.has(r1)
            if (r2 == 0) goto L23
            java.lang.String r1 = r6.getString(r1)
            r0.d = r1
        L23:
            java.lang.String r1 = "textColor"
            java.lang.String r1 = r6.optString(r1)
            java.lang.String r2 = "textColorDark"
            java.lang.String r2 = r6.optString(r2)
            r3 = 11
            java.lang.String r4 = ""
            if (r7 != r3) goto L3f
            boolean r1 = com.onetrust.otpublishers.headless.Internal.a.j(r2)
            if (r1 == 0) goto L3d
        L3b:
            r1 = r4
            goto L46
        L3d:
            r1 = r2
            goto L46
        L3f:
            boolean r2 = com.onetrust.otpublishers.headless.Internal.a.j(r1)
            if (r2 == 0) goto L46
            goto L3b
        L46:
            r0.b = r1
            r0.f = r1
            androidx.constraintlayout.motion.widget.n r1 = new androidx.constraintlayout.motion.widget.n
            r1.<init>()
            java.lang.String r2 = "color"
            java.lang.String r2 = r6.optString(r2)
            java.lang.String r5 = "colorDark"
            java.lang.String r5 = r6.optString(r5)
            if (r7 != r3) goto L66
            boolean r7 = com.onetrust.otpublishers.headless.Internal.a.j(r5)
            if (r7 == 0) goto L64
            goto L6e
        L64:
            r4 = r5
            goto L6e
        L66:
            boolean r7 = com.onetrust.otpublishers.headless.Internal.a.j(r2)
            if (r7 == 0) goto L6d
            goto L6e
        L6d:
            r4 = r2
        L6e:
            r1.e = r4
            java.lang.String r7 = "fontSize"
            com.google.android.gms.cloudmessaging.k r7 = e(r7, r6)
            r1.d = r7
            java.lang.String r7 = "borderRadius"
            boolean r2 = r6.has(r7)
            if (r2 == 0) goto L86
            java.lang.String r7 = r6.getString(r7)
            r1.i = r7
        L86:
            java.lang.String r7 = "showAsLink"
            boolean r2 = r6.has(r7)
            if (r2 == 0) goto L9a
            boolean r7 = r6.getBoolean(r7)
            r7 = r7 ^ 1
            java.lang.String r7 = java.lang.String.valueOf(r7)
            r1.k = r7
        L9a:
            java.lang.String r7 = "text"
            boolean r2 = r6.has(r7)
            if (r2 == 0) goto La8
            java.lang.String r6 = r6.getString(r7)
            r1.j = r6
        La8:
            r0.g = r1
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.d.a(org.json.JSONObject, int):androidx.camera.camera2.internal.c0");
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x0031  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.navigation.internal.m b(int r4, java.lang.String r5, org.json.JSONObject r6) {
        /*
            androidx.navigation.internal.m r0 = new androidx.navigation.internal.m
            r0.<init>()
            java.lang.String r1 = "titleTextAlign"
            boolean r2 = r6.has(r1)
            if (r2 == 0) goto L17
            java.lang.String r1 = r6.getString(r1)
            java.lang.String r1 = assistantMode.utils.studiableMetadata.b.n(r1)
            r0.f = r1
        L17:
            r0.g = r5
            java.lang.String r5 = "textColor"
            java.lang.String r5 = r6.optString(r5)
            java.lang.String r1 = "textColorDark"
            java.lang.String r1 = r6.optString(r1)
            r2 = 11
            java.lang.String r3 = ""
            if (r4 != r2) goto L35
            boolean r4 = com.onetrust.otpublishers.headless.Internal.a.j(r1)
            if (r4 == 0) goto L33
        L31:
            r5 = r3
            goto L3c
        L33:
            r5 = r1
            goto L3c
        L35:
            boolean r4 = com.onetrust.otpublishers.headless.Internal.a.j(r5)
            if (r4 == 0) goto L3c
            goto L31
        L3c:
            r0.b = r5
            java.lang.String r4 = "titleFontSize"
            com.google.android.gms.cloudmessaging.k r4 = e(r4, r6)
            r0.d = r4
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.d.b(int, java.lang.String, org.json.JSONObject):androidx.navigation.internal.m");
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0020  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.navigation.internal.m c(org.json.JSONObject r2, int r3, java.lang.String r4, java.lang.String r5, java.lang.String r6) {
        /*
            androidx.navigation.internal.m r0 = new androidx.navigation.internal.m
            r0.<init>()
            java.lang.String r4 = r2.optString(r4)
            java.lang.String r5 = r2.optString(r5)
            r1 = 11
            if (r3 != r1) goto L1a
            boolean r3 = com.onetrust.otpublishers.headless.Internal.a.j(r5)
            if (r3 == 0) goto L18
            goto L20
        L18:
            r4 = r5
            goto L22
        L1a:
            boolean r3 = com.onetrust.otpublishers.headless.Internal.a.j(r4)
            if (r3 == 0) goto L22
        L20:
            java.lang.String r4 = ""
        L22:
            r0.b = r4
            com.google.android.gms.cloudmessaging.k r2 = e(r6, r2)
            r0.d = r2
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.d.c(org.json.JSONObject, int, java.lang.String, java.lang.String, java.lang.String):androidx.navigation.internal.m");
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0042  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.navigation.internal.m d(org.json.JSONObject r3, org.json.JSONObject r4, int r5, java.lang.String r6) {
        /*
            androidx.navigation.internal.m r0 = new androidx.navigation.internal.m
            r0.<init>()
            java.lang.String r1 = "titleTextAlign"
            boolean r2 = r3.has(r1)
            if (r2 == 0) goto L17
            java.lang.String r1 = r3.getString(r1)
            java.lang.String r1 = assistantMode.utils.studiableMetadata.b.n(r1)
            r0.f = r1
        L17:
            boolean r1 = r4.has(r6)
            if (r1 == 0) goto L23
            java.lang.String r4 = r4.getString(r6)
            r0.g = r4
        L23:
            java.lang.String r4 = "titleTextColor"
            java.lang.String r4 = r3.optString(r4)
            java.lang.String r6 = "titleTextColorDark"
            java.lang.String r6 = r3.optString(r6)
            r1 = 11
            if (r5 != r1) goto L3c
            boolean r4 = com.onetrust.otpublishers.headless.Internal.a.j(r6)
            if (r4 == 0) goto L3a
            goto L42
        L3a:
            r4 = r6
            goto L44
        L3c:
            boolean r5 = com.onetrust.otpublishers.headless.Internal.a.j(r4)
            if (r5 == 0) goto L44
        L42:
            java.lang.String r4 = ""
        L44:
            r0.b = r4
            java.lang.String r4 = "titleFontSize"
            com.google.android.gms.cloudmessaging.k r3 = e(r4, r3)
            r0.d = r3
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.d.d(org.json.JSONObject, org.json.JSONObject, int, java.lang.String):androidx.navigation.internal.m");
    }

    public static k e(String str, JSONObject jSONObject) {
        k kVar = new k(9);
        if (jSONObject.has(str)) {
            kVar.d = jSONObject.getString(str);
        }
        return kVar;
    }

    public static com.quizlet.data.repository.user.e g(int i, JSONObject jSONObject, boolean z) {
        com.quizlet.data.repository.user.e eVar = new com.quizlet.data.repository.user.e();
        if (jSONObject.has(DTBMetricsConfiguration.APSMETRICS_URL)) {
            eVar.c = jSONObject.getString(DTBMetricsConfiguration.APSMETRICS_URL);
        }
        if (jSONObject.has("show")) {
            eVar.d = String.valueOf(jSONObject.getBoolean("show"));
        }
        eVar.b = AbstractC3625g4.g(jSONObject, i, z, null);
        return eVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x003d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.navigation.internal.m i(org.json.JSONObject r5, int r6) {
        /*
            androidx.navigation.internal.m r0 = new androidx.navigation.internal.m
            r0.<init>()
            java.lang.String r1 = "titleTextAlign"
            boolean r2 = r5.has(r1)
            if (r2 == 0) goto L17
            java.lang.String r1 = r5.getString(r1)
            java.lang.String r1 = assistantMode.utils.studiableMetadata.b.n(r1)
            r0.f = r1
        L17:
            java.lang.String r1 = "titleText"
            boolean r2 = r5.has(r1)
            if (r2 == 0) goto L25
            java.lang.String r1 = r5.getString(r1)
            r0.g = r1
        L25:
            java.lang.String r1 = "titleTextColor"
            java.lang.String r1 = r5.optString(r1)
            java.lang.String r2 = "titleTextColorDark"
            java.lang.String r2 = r5.optString(r2)
            r3 = 11
            java.lang.String r4 = ""
            if (r6 != r3) goto L41
            boolean r6 = com.onetrust.otpublishers.headless.Internal.a.j(r2)
            if (r6 == 0) goto L3f
        L3d:
            r1 = r4
            goto L48
        L3f:
            r1 = r2
            goto L48
        L41:
            boolean r6 = com.onetrust.otpublishers.headless.Internal.a.j(r1)
            if (r6 == 0) goto L48
            goto L3d
        L48:
            r0.b = r1
            java.lang.String r6 = "titleFontSize"
            com.google.android.gms.cloudmessaging.k r5 = e(r6, r5)
            r0.d = r5
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.d.i(org.json.JSONObject, int):androidx.navigation.internal.m");
    }

    /* JADX WARN: Removed duplicated region for block: B:6:0x001d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.navigation.internal.m l(org.json.JSONObject r5, int r6) {
        /*
            androidx.navigation.internal.m r0 = new androidx.navigation.internal.m
            r0.<init>()
            java.lang.String r1 = "titleTextColor"
            java.lang.String r1 = r5.optString(r1)
            java.lang.String r2 = "titleTextColorDark"
            java.lang.String r2 = r5.optString(r2)
            r3 = 11
            java.lang.String r4 = ""
            if (r6 != r3) goto L21
            boolean r6 = com.onetrust.otpublishers.headless.Internal.a.j(r2)
            if (r6 == 0) goto L1f
        L1d:
            r1 = r4
            goto L28
        L1f:
            r1 = r2
            goto L28
        L21:
            boolean r6 = com.onetrust.otpublishers.headless.Internal.a.j(r1)
            if (r6 == 0) goto L28
            goto L1d
        L28:
            r0.b = r1
            java.lang.String r6 = "titleShow"
            boolean r1 = r5.has(r6)
            if (r1 == 0) goto L38
            java.lang.String r6 = r5.getString(r6)
            r0.e = r6
        L38:
            java.lang.String r6 = "titleFontSize"
            com.google.android.gms.cloudmessaging.k r5 = e(r6, r5)
            r0.d = r5
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.d.l(org.json.JSONObject, int):androidx.navigation.internal.m");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0023  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.compose.runtime.internal.j m(org.json.JSONObject r5, int r6) {
        /*
            androidx.compose.runtime.internal.j r0 = new androidx.compose.runtime.internal.j
            r0.<init>()
            java.lang.String r1 = "textColor"
            boolean r2 = r5.has(r1)
            r3 = 11
            java.lang.String r4 = ""
            if (r2 == 0) goto L36
            java.lang.String r1 = r5.optString(r1)
            java.lang.String r2 = "textColorDark"
            java.lang.String r2 = r5.optString(r2)
            if (r6 != r3) goto L27
            boolean r1 = com.onetrust.otpublishers.headless.Internal.a.j(r2)
            if (r1 == 0) goto L25
        L23:
            r1 = r4
            goto L2e
        L25:
            r1 = r2
            goto L2e
        L27:
            boolean r2 = com.onetrust.otpublishers.headless.Internal.a.j(r1)
            if (r2 == 0) goto L2e
            goto L23
        L2e:
            r0.b = r1
            r0.c = r1
            r0.d = r1
            r0.f = r1
        L36:
            java.lang.String r1 = "backgroundColorDark"
            boolean r2 = r5.has(r1)
            if (r2 == 0) goto L5d
            java.lang.String r2 = "backgroundColor"
            java.lang.String r2 = r5.optString(r2)
            java.lang.String r5 = r5.optString(r1)
            if (r6 != r3) goto L53
            boolean r6 = com.onetrust.otpublishers.headless.Internal.a.j(r5)
            if (r6 == 0) goto L51
            goto L5b
        L51:
            r4 = r5
            goto L5b
        L53:
            boolean r5 = com.onetrust.otpublishers.headless.Internal.a.j(r2)
            if (r5 == 0) goto L5a
            goto L5b
        L5a:
            r4 = r2
        L5b:
            r0.a = r4
        L5d:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.d.m(org.json.JSONObject, int):androidx.compose.runtime.internal.j");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:115:0x0233  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x023e  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x025a  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x003b  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0046  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0054  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00a2  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00cb  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00d4  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00da  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00f4  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x010b  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x011a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.onetrust.otpublishers.headless.UI.UIProperty.e f(int r26) {
        /*
            Method dump skipped, instructions count: 1311
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.d.f(int):com.onetrust.otpublishers.headless.UI.UIProperty.e");
    }

    public final JSONObject h() {
        JSONObject jSONObject = this.b;
        return jSONObject.has("preferenceCenterData") ? jSONObject.getJSONObject("preferenceCenterData") : new JSONObject();
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0058  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00e5  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00f6  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0146  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x01f0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.airbnb.lottie.animation.keyframe.q j() {
        /*
            Method dump skipped, instructions count: 618
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.d.j():com.airbnb.lottie.animation.keyframe.q");
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x01a7  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x01ad  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x01b2  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x01fe  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x0227  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x0268  */
    /* JADX WARN: Removed duplicated region for block: B:160:0x029b  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x02ad  */
    /* JADX WARN: Removed duplicated region for block: B:167:0x02b6  */
    /* JADX WARN: Removed duplicated region for block: B:169:0x02bc  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00e9  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0117  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x013d  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0147  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0187  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x019e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.onetrust.otpublishers.headless.UI.UIProperty.g k(int r21) {
        /*
            Method dump skipped, instructions count: 707
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.d.k(int):com.onetrust.otpublishers.headless.UI.UIProperty.g");
    }

    public d(Context context, int i) {
        this.c = context;
        this.b = new com.onetrust.otpublishers.headless.Internal.Preferences.e(context).e();
        this.a = i;
    }
}
