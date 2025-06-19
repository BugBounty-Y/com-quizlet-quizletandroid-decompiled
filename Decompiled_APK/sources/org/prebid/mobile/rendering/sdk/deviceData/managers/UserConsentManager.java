package org.prebid.mobile.rendering.sdk.deviceData.managers;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import com.amazon.aps.ads.privacy.b;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABCCPAKeys;
import org.prebid.mobile.rendering.sdk.BaseManager;

/* loaded from: classes3.dex */
public class UserConsentManager extends BaseManager {
    public static final String[] i = {"IABTCF_gdprApplies", "IABTCF_TCString", "IABTCF_PurposeConsents", OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING, OTGppKeys.IAB_GPP_HDR_GPP_STRING, OTGppKeys.IAB_GPP_GPP_SID};
    public int b;
    public String c;
    public String d;
    public String e;
    public String f;
    public String g;
    public final SharedPreferences h;

    public UserConsentManager(Context context) {
        super(context);
        this.b = -1;
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(a());
        this.h = defaultSharedPreferences;
        defaultSharedPreferences.registerOnSharedPreferenceChangeListener(new b(this, 1));
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0051  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(android.content.SharedPreferences r14, java.lang.String r15) {
        /*
            r13 = this;
            if (r15 != 0) goto L4
            goto La7
        L4:
            int r0 = r15.hashCode()     // Catch: java.lang.Exception -> L26
            r1 = 3
            java.lang.String r2 = "IABTCF_PurposeConsents"
            java.lang.String r3 = "IABTCF_gdprApplies"
            r4 = 5
            java.lang.String r5 = "IABGPP_GppSID"
            r6 = 2
            java.lang.String r7 = "IABUSPrivacy_String"
            r8 = 1
            java.lang.String r9 = "IABTCF_TCString"
            r10 = 4
            java.lang.String r11 = "IABGPP_HDR_GppString"
            r12 = -1
            switch(r0) {
                case -2004976699: goto L49;
                case 83641339: goto L41;
                case 126060329: goto L39;
                case 743443760: goto L31;
                case 1218895378: goto L29;
                case 2023018157: goto L1e;
                default: goto L1d;
            }
        L1d:
            goto L51
        L1e:
            boolean r0 = r15.equals(r11)     // Catch: java.lang.Exception -> L26
            if (r0 == 0) goto L51
            r0 = r10
            goto L52
        L26:
            r14 = move-exception
            goto L8a
        L29:
            boolean r0 = r15.equals(r9)     // Catch: java.lang.Exception -> L26
            if (r0 == 0) goto L51
            r0 = r8
            goto L52
        L31:
            boolean r0 = r15.equals(r7)     // Catch: java.lang.Exception -> L26
            if (r0 == 0) goto L51
            r0 = r6
            goto L52
        L39:
            boolean r0 = r15.equals(r5)     // Catch: java.lang.Exception -> L26
            if (r0 == 0) goto L51
            r0 = r4
            goto L52
        L41:
            boolean r0 = r15.equals(r3)     // Catch: java.lang.Exception -> L26
            if (r0 == 0) goto L51
            r0 = 0
            goto L52
        L49:
            boolean r0 = r15.equals(r2)     // Catch: java.lang.Exception -> L26
            if (r0 == 0) goto L51
            r0 = r1
            goto L52
        L51:
            r0 = r12
        L52:
            if (r0 == 0) goto L83
            r3 = 0
            if (r0 == r8) goto L7c
            if (r0 == r6) goto L75
            if (r0 == r1) goto L6e
            if (r0 == r10) goto L67
            if (r0 == r4) goto L60
            goto La7
        L60:
            java.lang.String r14 = r14.getString(r5, r3)     // Catch: java.lang.Exception -> L26
            r13.g = r14     // Catch: java.lang.Exception -> L26
            return
        L67:
            java.lang.String r14 = r14.getString(r11, r3)     // Catch: java.lang.Exception -> L26
            r13.f = r14     // Catch: java.lang.Exception -> L26
            return
        L6e:
            java.lang.String r14 = r14.getString(r2, r3)     // Catch: java.lang.Exception -> L26
            r13.d = r14     // Catch: java.lang.Exception -> L26
            return
        L75:
            java.lang.String r14 = r14.getString(r7, r3)     // Catch: java.lang.Exception -> L26
            r13.e = r14     // Catch: java.lang.Exception -> L26
            return
        L7c:
            java.lang.String r14 = r14.getString(r9, r3)     // Catch: java.lang.Exception -> L26
            r13.c = r14     // Catch: java.lang.Exception -> L26
            return
        L83:
            int r14 = r14.getInt(r3, r12)     // Catch: java.lang.Exception -> L26
            r13.b = r14     // Catch: java.lang.Exception -> L26
            return
        L8a:
            java.lang.String r14 = android.util.Log.getStackTraceString(r14)
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r1 = "Failed to update "
            r0.<init>(r1)
            r0.append(r15)
            java.lang.String r15 = " "
            r0.append(r15)
            r0.append(r14)
            java.lang.String r14 = r0.toString()
            org.prebid.mobile.LogUtil.a(r14)
        La7:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.prebid.mobile.rendering.sdk.deviceData.managers.UserConsentManager.b(android.content.SharedPreferences, java.lang.String):void");
    }
}
