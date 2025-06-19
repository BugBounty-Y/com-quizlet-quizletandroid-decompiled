package com.perimeterx.mobile_sdk.configurations;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.onetrust.otpublishers.headless.Public.OTBannerHeightRatio;
import kotlin.NoWhenBranchMatchedException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class b {
    public static final b A;
    public static final b B;
    public static final b C;
    public static final b D;
    public static final b E;
    public static final b F;
    public static final b G;
    public static final b H;
    public static final b I;
    public static final b J;
    public static final b K;
    public static final b L;
    public static final b M;
    public static final b V;
    public static final b W;
    public static final b X;
    public static final b Y;
    public static final b Z;
    public static final com.onetrust.otpublishers.headless.Internal.Helper.h a;
    public static final b b;
    public static final b c;
    public static final b c1;
    public static final b d;
    public static final b d1;
    public static final b e;
    public static final b e1;
    public static final b f;
    public static final b f1;
    public static final b g;
    public static final b g1;
    public static final b h;
    public static final b h1;
    public static final b i;
    public static final b i1;
    public static final b j;
    public static final b j1;
    public static final b k;
    public static final b k1;
    public static final b l;
    public static final b l1;
    public static final b m;
    public static final b m1;
    public static final b n;
    public static final b n1;
    public static final b o;
    public static final b o1;
    public static final b p;
    public static final b p1;
    public static final b q;
    public static final b q1;
    public static final b r;
    public static final /* synthetic */ b[] r1;
    public static final b s;
    public static final b t;
    public static final b u;
    public static final b v;
    public static final b w;
    public static final b x;
    public static final b y;
    public static final b z;

    static {
        b bVar = new b("TRUE_VALUE", 0);
        b = bVar;
        b bVar2 = new b("FALSE_VALUE", 1);
        c = bVar2;
        b bVar3 = new b("UUID", 2);
        d = bVar3;
        b bVar4 = new b("TAG", 3);
        e = bVar4;
        b bVar5 = new b("FTAG", 4);
        f = bVar5;
        b bVar6 = new b("PAYLOAD", 5);
        g = bVar6;
        b bVar7 = new b("SID", 6);
        h = bVar7;
        b bVar8 = new b("VID", 7);
        i = bVar8;
        b bVar9 = new b("APPID", 8);
        j = bVar9;
        b bVar10 = new b("NOT_AVAILABLE", 9);
        k = bVar10;
        b bVar11 = new b("NO_INTERNET", 10);
        b bVar12 = new b("WIFI", 11);
        l = bVar12;
        b bVar13 = new b("CELLULAR", 12);
        m = bVar13;
        b bVar14 = new b("ANDROID", 13);
        n = bVar14;
        b bVar15 = new b("TYPE", 14);
        o = bVar15;
        b bVar16 = new b("DATA", 15);
        p = bVar16;
        b bVar17 = new b("G", 16);
        q = bVar17;
        b bVar18 = new b("R", 17);
        r = bVar18;
        b bVar19 = new b("P", 18);
        s = bVar19;
        b bVar20 = new b("MOBILE", 19);
        b bVar21 = new b("DEVICE_OS_VERSION", 20);
        t = bVar21;
        b bVar22 = new b("APP_ID", 21);
        b bVar23 = new b("DEVICE_OS_NAME", 22);
        u = bVar23;
        b bVar24 = new b("SDK_VERSION", 23);
        v = bVar24;
        b bVar25 = new b("APP_VERSION", 24);
        b bVar26 = new b("DEVICE_MODEL", 25);
        w = bVar26;
        b bVar27 = new b("ERROR_MISSING_VALUE", 26);
        x = bVar27;
        b bVar28 = new b("ERROR_FETCHING_VALUE", 27);
        b bVar29 = new b("ACTIVITY_REASON_NEW_SESSION", 28);
        y = bVar29;
        b bVar30 = new b("ACTIVITY_REASON_TOKEN_SCHEDULED_UPDATE", 29);
        z = bVar30;
        b bVar31 = new b("ACTIVITY_REASON_APP_RETURNED_FROM_BACKGROUND", 30);
        A = bVar31;
        b bVar32 = new b("ACTIVITY_REASON_REQUEST_WAS_BLOCKED", 31);
        B = bVar32;
        b bVar33 = new b("ACTIVITY_REASON_MISSING_TOKEN_AFTER_CHALLENGE_SOLVED", 32);
        C = bVar33;
        b bVar34 = new b("ACTIVITY_REASON_FIRST_TOUCH_EVENT", 33);
        D = bVar34;
        b bVar35 = new b("ACTIVITY_REASON_SCHEDULED_REPORT", 34);
        E = bVar35;
        b bVar36 = new b("ACTIVITY_REASON_CAPACITY_IS_FULL", 35);
        F = bVar36;
        b bVar37 = new b("ACTIVITY_REASON_APP_WENT_TO_BACKGROUND", 36);
        G = bVar37;
        b bVar38 = new b("ACTIVITY_REASON_HYBRID_APP_EVENT", 37);
        H = bVar38;
        b bVar39 = new b("ACTIVITY_REASON_ACCOUNT_DEFENDER_EVENT", 38);
        I = bVar39;
        b bVar40 = new b("BATTERY_STATUS_MISSING", 39);
        b bVar41 = new b("BATTERY_STATUS_UNKNOWN", 40);
        J = bVar41;
        b bVar42 = new b("BATTERY_STATUS_CHARGING", 41);
        K = bVar42;
        b bVar43 = new b("BATTERY_STATUS_DISCHARGING", 42);
        L = bVar43;
        b bVar44 = new b("BATTERY_STATUS_NOT_CHARGING", 43);
        M = bVar44;
        b bVar45 = new b("BATTERY_STATUS_FULL", 44);
        V = bVar45;
        b bVar46 = new b("BATTERY_PLUGGED_MISSING", 45);
        W = bVar46;
        b bVar47 = new b("BATTERY_PLUGGED_AC", 46);
        X = bVar47;
        b bVar48 = new b("BATTERY_PLUGGED_USB", 47);
        Y = bVar48;
        b bVar49 = new b("BATTERY_PLUGGED_WIRELESS", 48);
        Z = bVar49;
        b bVar50 = new b("BATTERY_HEALTH_MISSING", 49);
        c1 = bVar50;
        b bVar51 = new b("BATTERY_HEALTH_UNKNOWN", 50);
        d1 = bVar51;
        b bVar52 = new b("BATTERY_HEALTH_GOOD", 51);
        e1 = bVar52;
        b bVar53 = new b("BATTERY_HEALTH_OVERHEAT", 52);
        f1 = bVar53;
        b bVar54 = new b("BATTERY_HEALTH_DEAD", 53);
        g1 = bVar54;
        b bVar55 = new b("BATTERY_HEALTH_OVER_VOLTAGE", 54);
        h1 = bVar55;
        b bVar56 = new b("BATTERY_HEALTH_UNSPECIFIED_FAILURE", 55);
        i1 = bVar56;
        b bVar57 = new b("BATTERY_HEALTH_COLD", 56);
        j1 = bVar57;
        b bVar58 = new b("MESSAGE", 57);
        k1 = bVar58;
        b bVar59 = new b("SDK_CRASH", 58);
        l1 = bVar59;
        b bVar60 = new b("NETWORK_UNKNOWN", 59);
        m1 = bVar60;
        b bVar61 = new b("NETWORK_2G", 60);
        n1 = bVar61;
        b bVar62 = new b("NETWORK_3G", 61);
        o1 = bVar62;
        b bVar63 = new b("NETWORK_4G", 62);
        p1 = bVar63;
        b bVar64 = new b("NETWORK_5G", 63);
        q1 = bVar64;
        b[] bVarArr = {bVar, bVar2, bVar3, bVar4, bVar5, bVar6, bVar7, bVar8, bVar9, bVar10, bVar11, bVar12, bVar13, bVar14, bVar15, bVar16, bVar17, bVar18, bVar19, bVar20, bVar21, bVar22, bVar23, bVar24, bVar25, bVar26, bVar27, bVar28, bVar29, bVar30, bVar31, bVar32, bVar33, bVar34, bVar35, bVar36, bVar37, bVar38, bVar39, bVar40, bVar41, bVar42, bVar43, bVar44, bVar45, bVar46, bVar47, bVar48, bVar49, bVar50, bVar51, bVar52, bVar53, bVar54, bVar55, bVar56, bVar57, bVar58, bVar59, bVar60, bVar61, bVar62, bVar63, bVar64};
        r1 = bVarArr;
        AbstractC3328d.f(bVarArr);
        a = new com.onetrust.otpublishers.headless.Internal.Helper.h(22);
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) r1.clone();
    }

    public final String a() {
        switch (ordinal()) {
            case 0:
                return "true";
            case 1:
                return "false";
            case 2:
                return "uuid";
            case 3:
                return "tag";
            case 4:
                return "ftag";
            case 5:
                return "payload";
            case 6:
                return "sid";
            case 7:
                return "vid";
            case 8:
                return "appId";
            case 9:
                return "NA";
            case 10:
                return "No internet";
            case 11:
                return "WiFi";
            case 12:
                return "Mobile";
            case 13:
                return "Android";
            case 14:
                return "t";
            case 15:
                return "d";
            case 16:
                return "g";
            case 17:
                return "r";
            case 18:
                return "p";
            case 19:
                return DTBMetricsConfiguration.APSMETRICS_LEVEL2_KEY;
            case 20:
                return "device_os_version";
            case 21:
                return "app_id";
            case EventType.WINDOW_STATE /* 22 */:
                return "device_os_name";
            case EventType.AUDIO /* 23 */:
                return "sdk_version";
            case EventType.VIDEO /* 24 */:
                return "app_version";
            case EventType.SUBS /* 25 */:
                return "device_model";
            case EventType.CDN /* 26 */:
                return "missing_value";
            case 27:
                return "error_fetching_value";
            case 28:
                return "new_session";
            case 29:
                return "token_scheduled_update";
            case 30:
                return "app returned from background";
            case 31:
                return "request was blocked";
            case 32:
                return "missing token after challenge solved";
            case 33:
                return "first touch event";
            case 34:
                return "scheduled report";
            case 35:
                return "capacity is full";
            case 36:
                return "app went to background";
            case 37:
                return "hybrid app event";
            case 38:
                return "account defender event";
            case 39:
                return "";
            case RequestError.NETWORK_FAILURE /* 40 */:
                return DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
            case RequestError.NO_DEV_KEY /* 41 */:
                return "charging";
            case 42:
                return "discharging";
            case 43:
                return "not charging";
            case 44:
                return OTBannerHeightRatio.FULL;
            case 45:
                return "";
            case 46:
                return "AC";
            case 47:
                return "USB";
            case 48:
                return "Wireless";
            case 49:
                return "";
            case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                return DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
            case 51:
                return "good";
            case 52:
                return "overheat";
            case 53:
                return "dead";
            case 54:
                return "over voltage";
            case 55:
                return "unspecified failure";
            case 56:
                return "cold";
            case 57:
                return "message";
            case 58:
                return "sdk_crash";
            case 59:
                return "Unknown";
            case 60:
                return "2G";
            case 61:
                return "3G";
            case 62:
                return "4G";
            case 63:
                return "5G";
            default:
                throw new NoWhenBranchMatchedException();
        }
    }
}
