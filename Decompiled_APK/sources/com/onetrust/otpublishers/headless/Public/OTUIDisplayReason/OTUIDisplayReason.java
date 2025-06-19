package com.onetrust.otpublishers.headless.Public.OTUIDisplayReason;

import android.support.v4.media.session.a;
import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;

/* loaded from: classes2.dex */
public class OTUIDisplayReason {
    public final String a;
    public final int b;
    public final String c;

    public OTUIDisplayReason(int i, @NonNull String str) {
        this.b = i;
        this.c = str;
        this.a = i + " - " + str;
    }

    public int getResponseCode() {
        return this.b;
    }

    @NonNull
    public String getResponseMessage() {
        return this.c;
    }

    @NonNull
    public String logReason() {
        return this.a;
    }

    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder("OTUIDisplayReason{logMessage='");
        sb.append(this.a);
        sb.append("', responseCode=");
        sb.append(this.b);
        sb.append(", responseMessage='");
        return a.t(sb, this.c, "'}");
    }

    @NonNull
    public static String getResponseMessage(int i) {
        switch (i) {
            case 101:
                break;
            case 102:
                break;
            case 103:
                break;
            case 104:
                break;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED /* 105 */:
                break;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF /* 106 */:
                break;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED /* 107 */:
                break;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY /* 108 */:
                break;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION /* 109 */:
                break;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED /* 110 */:
                break;
            case 111:
                break;
            default:
                switch (i) {
                }
        }
        return "Displaying OT Banner because new category or purpose addition is detected.";
    }
}
