package com.pubmatic.sdk.common;

import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public class h {
    public static final int AD_ALREADY_SHOWN = 2001;
    public static final int AD_EXPIRED = 1011;
    public static final int AD_NOT_READY = 2002;
    public static final int AD_REQUEST_NOT_ALLOWED = 1012;
    public static final int CLIENT_SIDE_AUCTION_LOST = 3001;
    public static final int INTERNAL_ERROR = 1006;
    public static final int INVALID_CONFIG = 1013;
    public static final int INVALID_REQUEST = 1001;
    public static final int INVALID_RESPONSE = 1007;
    public static final int INVALID_REWARD_SELECTED = 5001;
    public static final int NETWORK_ERROR = 1003;
    public static final int NO_ADS_AVAILABLE = 1002;
    public static final int OPENWRAP_SIGNALING_ERROR = 1010;
    public static final int RENDER_ERROR = 1009;
    public static final int REQUEST_CANCELLED = 1008;
    public static final int REWARD_NOT_SELECTED = 5002;
    public static final int SERVER_ERROR = 1004;
    public static final int TIMEOUT_ERROR = 1005;
    private int a;

    @NonNull
    private String b;
    private Map<String, Object> c;

    public h(int i, @NonNull String str) {
        this.a = i;
        if (i == 2001) {
            this.b = AbstractC0147y.d("ALREADY_SHOWN: ", str);
            return;
        }
        if (i == 2002) {
            this.b = AbstractC0147y.d("NOT_READY: ", str);
            return;
        }
        if (i == 3001) {
            this.b = AbstractC0147y.d("CLIENT_SIDE_AUCTION_LOST: ", str);
            return;
        }
        if (i == 5001) {
            this.b = AbstractC0147y.d("INVALID_REWARD_SELECTED: ", str);
            return;
        }
        if (i == 5002) {
            this.b = AbstractC0147y.d("REWARD_NOT_SELECTED: ", str);
            return;
        }
        switch (i) {
            case 1001:
                this.b = AbstractC0147y.d("INVALID_REQUEST: ", str);
                break;
            case 1002:
                this.b = AbstractC0147y.d("NO_ADS_AVAILABLE: ", str);
                break;
            case 1003:
                this.b = AbstractC0147y.d("NETWORK_ERROR: ", str);
                break;
            case 1004:
                this.b = AbstractC0147y.d("SERVER_ERROR: ", str);
                break;
            case 1005:
                this.b = AbstractC0147y.d("TIMEOUT_ERROR: ", str);
                break;
            case 1006:
                this.b = AbstractC0147y.d("INTERNAL_ERROR: ", str);
                break;
            case 1007:
                this.b = AbstractC0147y.d("INVALID_RESPONSE: ", str);
                break;
            case 1008:
                this.b = AbstractC0147y.d("REQUEST_CANCELLED: ", str);
                break;
            case 1009:
                this.b = AbstractC0147y.d("RENDER_ERROR: ", str);
                break;
            case 1010:
                this.b = AbstractC0147y.d("OPENWRAP_SIGNALING_ERROR: ", str);
                break;
            case AD_EXPIRED /* 1011 */:
                this.b = AbstractC0147y.d("AD_EXPIRED: ", str);
                break;
            case 1012:
                this.b = AbstractC0147y.d("AD_REQUEST_NOT_ALLOWED: ", str);
                break;
            default:
                this.b = str;
                break;
        }
    }

    public void addExtraInfo(String str, Object obj) {
        if (this.c == null) {
            this.c = new HashMap();
        }
        this.c.put(str, obj);
    }

    public int getErrorCode() {
        return this.a;
    }

    @NonNull
    public String getErrorMessage() {
        return this.b;
    }

    public Map<String, Object> getExtraInfo() {
        return this.c;
    }

    @Deprecated
    public void setErrorCode(int i) {
        this.a = i;
    }

    @Deprecated
    public void setErrorMessage(@NonNull String str) {
        this.b = str;
    }

    public void setExtraInfo(Map<String, Object> map) {
        this.c = map;
    }

    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder("POBError{errorCode=");
        sb.append(this.a);
        sb.append(", errorMessage='");
        return android.support.v4.media.session.a.t(sb, this.b, "'}");
    }

    public Object getExtraInfo(String str) {
        Map<String, Object> map = this.c;
        if (map != null) {
            return map.get(str);
        }
        return null;
    }
}
