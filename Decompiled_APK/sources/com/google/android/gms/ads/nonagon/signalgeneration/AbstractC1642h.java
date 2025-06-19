package com.google.android.gms.ads.nonagon.signalgeneration;

import android.os.Bundle;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.AbstractC2096gb;
import com.google.android.gms.internal.ads.HA;
import com.google.android.gms.internal.measurement.P1;
import com.google.android.gms.internal.mlkit_vision_camera.C3316a;
import com.google.android.gms.internal.mlkit_vision_common.C3419a;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C3644j;
import com.google.android.gms.internal.play_billing.V0;
import java.util.Collections;
import java.util.HashMap;

/* renamed from: com.google.android.gms.ads.nonagon.signalgeneration.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract /* synthetic */ class AbstractC1642h {
    public static /* synthetic */ String A(int i) {
        switch (i) {
            case 1:
                return "CLIENT_UPLOAD_ELIGIBILITY_UNKNOWN";
            case 2:
                return "CLIENT_UPLOAD_ELIGIBLE";
            case 3:
                return "MEASUREMENT_SERVICE_NOT_ENABLED";
            case 4:
                return "ANDROID_TOO_OLD";
            case 5:
                return "NON_PLAY_MODE";
            case 6:
                return "SDK_TOO_OLD";
            case 7:
                return "MISSING_JOB_SCHEDULER";
            case 8:
                return "NOT_ENABLED_IN_MANIFEST";
            case 9:
                return "CLIENT_FLAG_OFF";
            case 10:
                return "SERVICE_FLAG_OFF";
            case 11:
                return "PINNED_TO_SERVICE_UPLOAD";
            case 12:
                return "MISSING_SGTM_SERVER_URL";
            default:
                throw null;
        }
    }

    public static /* synthetic */ String B(int i) {
        return i != 1 ? i != 2 ? i != 3 ? "null" : "VIDEO" : "NATIVE_DISPLAY" : "HTML_DISPLAY";
    }

    public static int a(int i) {
        switch (i) {
            case 0:
                return 1;
            case 1:
                return 2;
            case 2:
                return 3;
            case 3:
                return 4;
            case 4:
                return 5;
            case 5:
                return 6;
            case 6:
                return 7;
            case 7:
                return 8;
            case 8:
                return 9;
            default:
                switch (i) {
                    case 20:
                        return 10;
                    case 21:
                        return 11;
                    case EventType.WINDOW_STATE /* 22 */:
                        return 12;
                    default:
                        return 0;
                }
        }
    }

    public static /* synthetic */ String b(int i) {
        switch (i) {
            case 1:
                return "api-call";
            case 2:
                return "dynamite-enter";
            case 3:
                return "read-from-disk-start";
            case 4:
                return "read-from-disk-end";
            case 5:
                return "client-signals-start";
            case 6:
                return "client-signals-end";
            case 7:
                return "service-connected";
            case 8:
                return "gms-signals-start";
            case 9:
                return "gms-signals-end";
            case 10:
                return "get-signals-sdkcore-start";
            case 11:
                return "get-signals-sdkcore-end";
            case 12:
                return "get-ad-dictionary-sdkcore-start";
            case 13:
                return "get-ad-dictionary-sdkcore-end";
            case 14:
                return "http-response-ready";
            case 15:
                return "scar-preloader-ready";
            case 16:
                return "scar-preloader-processing-done";
            case 17:
                return "normalize-ad-response-start";
            case 18:
                return "normalize-ad-response-end";
            case 19:
                return "binder-call-start";
            case 20:
                return "server-response-parse-start";
            case 21:
                return "rendering-start";
            case EventType.WINDOW_STATE /* 22 */:
                return "public-api-callback";
            case EventType.AUDIO /* 23 */:
                return "rendering-native-ads-native-js-webview-start";
            case EventType.VIDEO /* 24 */:
                return "rendering-native-ads-preprocess-start";
            case EventType.SUBS /* 25 */:
                return "rendering-native-ads-preprocess-end";
            case EventType.CDN /* 26 */:
                return "rendering-native-assets-loading-start";
            case 27:
                return "rendering-native-assets-loading-end";
            case 28:
                return "rendering-webview-creation-start";
            case 29:
                return "rendering-webview-creation-end";
            case 30:
                return "rendering-ad-component-creation-end";
            case 31:
                return "rendering-configure-webview-start";
            case 32:
                return "rendering-configure-webview-end";
            case 33:
                return "rendering-webview-load-html-start";
            case 34:
                return "rendering-webview-load-html-end";
            case 35:
                return "type2-fetch-start";
            case 36:
                return "type2-fetch-end";
            case 37:
                return "sod-validation-start";
            case 38:
                return "sod-validation-end";
            case 39:
                return "sod-cache-key-start";
            case RequestError.NETWORK_FAILURE /* 40 */:
                return "sod-cache-key-end";
            case RequestError.NO_DEV_KEY /* 41 */:
                return "sod-read-and-remove-start";
            case 42:
                return "sod-read-and-remove-end";
            case 43:
                return "sod-decode-start";
            case 44:
                return "sod-decode-end";
            case 45:
                return "native-assets-loading-basic-start";
            case 46:
                return "native-assets-loading-basic-end";
            case 47:
                return "native-assets-loading-image-start";
            case 48:
                return "native-assets-loading-image-end";
            case 49:
                return "native-assets-loading-image-composition-start";
            case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                return "native-assets-loading-image-composition-end";
            case 51:
                return "native-assets-loading-logo-start";
            case 52:
                return "native-assets-loading-logo-end";
            case 53:
                return "native-assets-loading-icon-start";
            case 54:
                return "native-assets-loading-icon-end";
            case 55:
                return "native-assets-loading-attribution-start";
            case 56:
                return "native-assets-loading-attribution-end";
            case 57:
                return "native-assets-loading-video-start";
            case 58:
                return "native-assets-loading-video-end";
            case 59:
                return "native-assets-loading-video-composition-start";
            case 60:
                return "native-assets-loading-media-start";
            case 61:
                return "native-assets-loading-media-end";
            case 62:
                return "native-assets-loading-custom-start";
            case 63:
                return "native-assets-loading-custom-end";
            case 64:
                return "native-assets-loading-omid-start";
            case 65:
                return "native-assets-loading-omid-end";
            default:
                throw null;
        }
    }

    public static /* synthetic */ String c(int i) {
        if (i == 1) {
            return "htmlDisplay";
        }
        if (i == 2) {
            return "nativeDisplay";
        }
        if (i == 3) {
            return com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_VIDEO;
        }
        throw null;
    }

    public static /* synthetic */ String d(int i) {
        if (i == 1) {
            return "beginToRender";
        }
        if (i == 2) {
            return "definedByJavascript";
        }
        if (i == 3) {
            return "onePixel";
        }
        if (i == 4) {
            return "unspecified";
        }
        throw null;
    }

    public static /* synthetic */ int e(int i) {
        if (i == 1) {
            return 0;
        }
        if (i == 2) {
            return 1;
        }
        if (i == 3) {
            return 1000;
        }
        throw null;
    }

    public static /* synthetic */ int f(int i) {
        switch (i) {
            case 1:
                return 0;
            case 2:
                return 1;
            case 3:
                return 2;
            case 4:
                return 3;
            case 5:
                return 4;
            case 6:
                return 5;
            case 7:
                return 6;
            case 8:
                return 7;
            case 9:
                return 8;
            case 10:
                return 20;
            case 11:
                return 21;
            case 12:
                return 22;
            default:
                throw null;
        }
    }

    public static int g(int i, int i2, int i3) {
        return HA.C(i) + i2 + i3;
    }

    public static int h(int i, int i2, int i3, int i4) {
        return HA.C(i) + i2 + i3 + i4;
    }

    public static int i(int i, int i2, int i3, int i4, int i5) {
        return Math.max(((i * i2) / i3) + i4, i5);
    }

    public static com.google.android.gms.internal.mlkit_vision_barcode.H j(HashMap map, int i) {
        Collections.unmodifiableMap(new HashMap(map));
        return new com.google.android.gms.internal.mlkit_vision_barcode.H(i);
    }

    public static C3316a k(HashMap map, int i) {
        Collections.unmodifiableMap(new HashMap(map));
        return new C3316a(i);
    }

    public static C3419a l(HashMap map, int i) {
        Collections.unmodifiableMap(new HashMap(map));
        return new C3419a(i);
    }

    public static C3644j m(HashMap map, int i) {
        Collections.unmodifiableMap(new HashMap(map));
        return new C3644j(i);
    }

    public static HashMap n(Class cls, com.google.android.gms.internal.mlkit_vision_barcode.H h) {
        HashMap map = new HashMap();
        map.put(cls, h);
        return map;
    }

    public static HashMap o(Class cls, C3316a c3316a) {
        HashMap map = new HashMap();
        map.put(cls, c3316a);
        return map;
    }

    public static HashMap p(Class cls, C3419a c3419a) {
        HashMap map = new HashMap();
        map.put(cls, c3419a);
        return map;
    }

    public static HashMap q(Class cls, C3644j c3644j) {
        HashMap map = new HashMap();
        map.put(cls, c3644j);
        return map;
    }

    public static /* synthetic */ void r(int i) {
        if (i == 0) {
            throw new NullPointerException("null reference");
        }
    }

    public static void s(int i, String str, String str2) {
        AbstractC2096gb.J(str2, str + i);
    }

    public static void t(com.google.android.gms.common.util.b bVar, Bundle bundle, String str) {
        bVar.getClass();
        bundle.putLong(str, System.currentTimeMillis());
    }

    public static void u(String str, String str2, String str3) {
        AbstractC2096gb.J(str3, str2.concat(String.valueOf(str)));
    }

    public static void v(HashMap map) {
        Collections.unmodifiableMap(new HashMap(map));
    }

    public static int w(int i, int i2, int i3) {
        return P1.q(i) + i2 + i3;
    }

    public static int x(int i, int i2, int i3, int i4) {
        return P1.q(i) + i2 + i3 + i4;
    }

    public static int y(int i, int i2, int i3) {
        return V0.e0(i) + i2 + i3;
    }

    public static int z(int i, int i2, int i3, int i4) {
        return V0.e0(i) + i2 + i3 + i4;
    }
}
