package com.google.android.gms.internal.ads;

import com.comscore.streaming.EventType;

/* loaded from: classes2.dex */
public final class U3 implements RA {
    public final /* synthetic */ int a;
    public static final U3 b = new U3(0);
    public static final U3 c = new U3(1);
    public static final U3 d = new U3(2);
    public static final U3 e = new U3(3);
    public static final U3 f = new U3(4);
    public static final U3 g = new U3(5);
    public static final U3 h = new U3(6);
    public static final U3 i = new U3(7);
    public static final U3 j = new U3(8);
    public static final U3 k = new U3(9);
    public static final U3 l = new U3(10);
    public static final U3 m = new U3(11);
    public static final U3 n = new U3(12);
    public static final U3 o = new U3(13);
    public static final U3 p = new U3(14);
    public static final U3 q = new U3(15);
    public static final U3 r = new U3(16);
    public static final U3 s = new U3(17);
    public static final U3 t = new U3(18);
    public static final U3 u = new U3(19);
    public static final U3 v = new U3(20);
    public static final U3 w = new U3(21);
    public static final U3 x = new U3(22);
    public static final U3 y = new U3(23);
    public static final U3 z = new U3(24);
    public static final U3 A = new U3(25);
    public static final U3 B = new U3(26);
    public static final U3 C = new U3(27);
    public static final U3 D = new U3(28);
    public static final U3 E = new U3(29);

    public /* synthetic */ U3(int i2) {
        this.a = i2;
    }

    @Override // com.google.android.gms.internal.ads.RA
    public final boolean zza(int i2) {
        EnumC2515q6 enumC2515q6;
        EnumC1867b7 enumC1867b7;
        switch (this.a) {
            case 0:
                if (i2 == 0 || i2 == 1 || i2 == 2) {
                }
                break;
            case 1:
                if (i2 == 0 || i2 == 1 || i2 == 2) {
                }
                break;
            case 2:
                switch (i2) {
                }
            case 3:
                switch (i2) {
                }
            case 4:
                if (i2 == 0 || i2 == 1) {
                }
                break;
            case 5:
                if (i2 == 0 || i2 == 1 || i2 == 2 || i2 == 3 || i2 == 4) {
                }
                break;
            case 6:
                if (AbstractC1795We.b(i2) != 0) {
                }
                break;
            case 7:
                switch (i2) {
                }
            case 8:
                if (i2 == 0 || i2 == 1 || i2 == 2 || i2 == 1000) {
                }
                break;
            case 9:
                if (i2 == 0 || i2 == 1 || i2 == 2 || i2 == 3 || i2 == 4) {
                }
                break;
            case 10:
                switch (i2) {
                    case 0:
                        enumC2515q6 = EnumC2515q6.AD_INITIATER_UNSPECIFIED;
                        break;
                    case 1:
                        enumC2515q6 = EnumC2515q6.BANNER;
                        break;
                    case 2:
                        enumC2515q6 = EnumC2515q6.DFP_BANNER;
                        break;
                    case 3:
                        enumC2515q6 = EnumC2515q6.INTERSTITIAL;
                        break;
                    case 4:
                        enumC2515q6 = EnumC2515q6.DFP_INTERSTITIAL;
                        break;
                    case 5:
                        enumC2515q6 = EnumC2515q6.NATIVE_EXPRESS;
                        break;
                    case 6:
                        enumC2515q6 = EnumC2515q6.AD_LOADER;
                        break;
                    case 7:
                        enumC2515q6 = EnumC2515q6.REWARD_BASED_VIDEO_AD;
                        break;
                    case 8:
                        enumC2515q6 = EnumC2515q6.BANNER_SEARCH_ADS;
                        break;
                    case 9:
                        enumC2515q6 = EnumC2515q6.GOOGLE_MOBILE_ADS_SDK_ADAPTER;
                        break;
                    case 10:
                        enumC2515q6 = EnumC2515q6.APP_OPEN;
                        break;
                    case 11:
                        enumC2515q6 = EnumC2515q6.REWARDED_INTERSTITIAL;
                        break;
                    default:
                        enumC2515q6 = null;
                        break;
                }
                if (enumC2515q6 != null) {
                }
                break;
            case 11:
                if (i2 == 0 || i2 == 1 || i2 == 2 || i2 == 4) {
                }
                break;
            case 12:
                if (i2 == 0 || i2 == 1 || i2 == 2) {
                }
                break;
            case 13:
                if ((i2 != 0 ? i2 != 1 ? i2 != 2 ? i2 != 3 ? i2 != 4 ? i2 != 5 ? null : EnumC2901z6.SUSPENDED : EnumC2901z6.DISCONNECTED : EnumC2901z6.DISCONNECTING : EnumC2901z6.CONNECTED : EnumC2901z6.CONNECTING : EnumC2901z6.UNSPECIFIED) != null) {
                }
                break;
            case 14:
                if (i2 == 0 || i2 == 1 || i2 == 2 || i2 == 3) {
                }
                break;
            case 15:
                if (i2 == 0 || i2 == 1) {
                }
                break;
            case 16:
                switch (i2) {
                    case 0:
                        enumC1867b7 = EnumC1867b7.AD_FORMAT_TYPE_UNSPECIFIED;
                        break;
                    case 1:
                        enumC1867b7 = EnumC1867b7.BANNER;
                        break;
                    case 2:
                        enumC1867b7 = EnumC1867b7.INTERSTITIAL;
                        break;
                    case 3:
                        enumC1867b7 = EnumC1867b7.NATIVE_EXPRESS;
                        break;
                    case 4:
                        enumC1867b7 = EnumC1867b7.NATIVE_CONTENT;
                        break;
                    case 5:
                        enumC1867b7 = EnumC1867b7.NATIVE_APP_INSTALL;
                        break;
                    case 6:
                        enumC1867b7 = EnumC1867b7.NATIVE_CUSTOM_TEMPLATE;
                        break;
                    case 7:
                        enumC1867b7 = EnumC1867b7.DFP_BANNER;
                        break;
                    case 8:
                        enumC1867b7 = EnumC1867b7.DFP_INTERSTITIAL;
                        break;
                    case 9:
                        enumC1867b7 = EnumC1867b7.REWARD_BASED_VIDEO_AD;
                        break;
                    case 10:
                        enumC1867b7 = EnumC1867b7.BANNER_SEARCH_ADS;
                        break;
                    default:
                        enumC1867b7 = null;
                        break;
                }
                if (enumC1867b7 != null) {
                }
                break;
            case 17:
                if (i2 == 0 || i2 == 1 || i2 == 2) {
                }
                break;
            case 18:
                if (i2 == 0 || i2 == 1 || i2 == 1000) {
                }
                break;
            case 19:
                if (i2 == 1 || i2 == 2) {
                }
                break;
            case 20:
                if (i2 == 0 || i2 == 1) {
                }
                break;
            case 21:
                if (i2 != 0 && i2 != 1 && i2 != 2 && i2 != 1999) {
                    switch (i2) {
                    }
                }
                break;
            case EventType.WINDOW_STATE /* 22 */:
                if (i2 == 0 || i2 == 1) {
                }
                break;
            case EventType.AUDIO /* 23 */:
                if (i2 == 0 || i2 == 1 || i2 == 2 || i2 == 3) {
                }
                break;
            case EventType.VIDEO /* 24 */:
                if (i2 == 0 || i2 == 1 || i2 == 2 || i2 == 3 || i2 == 4 || i2 == 5) {
                }
                break;
            case EventType.SUBS /* 25 */:
                if (i2 == 0 || i2 == 1 || i2 == 2 || i2 == 3) {
                }
                break;
            case EventType.CDN /* 26 */:
                switch (i2) {
                }
            case 27:
                switch (i2) {
                }
            case 28:
                if (i2 == 0 || i2 == 1 || i2 == 2 || i2 == 3 || i2 == 4 || i2 == 5) {
                }
                break;
            default:
                if (i2 == 0 || i2 == 1 || i2 == 2 || i2 == 3 || i2 == 4) {
                }
                break;
        }
        return true;
    }
}
