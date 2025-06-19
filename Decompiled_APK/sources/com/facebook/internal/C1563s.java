package com.facebook.internal;

import android.content.SharedPreferences;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.facebook.internal.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1563s {
    public static final C1563s a = new C1563s();
    public static final HashMap b = new HashMap();

    public static final void a(InterfaceC1561p callback, EnumC1562q feature) {
        Intrinsics.checkNotNullParameter(feature, "feature");
        Intrinsics.checkNotNullParameter(callback, "callback");
        u.c(new r(callback, feature));
    }

    public static final boolean b(EnumC1562q feature) {
        boolean z;
        Intrinsics.checkNotNullParameter(feature, "feature");
        boolean z2 = false;
        if (EnumC1562q.Unknown != feature) {
            if (EnumC1562q.Core != feature) {
                SharedPreferences sharedPreferences = com.facebook.o.a().getSharedPreferences("com.facebook.internal.FEATURE_MANAGER", 0);
                feature.getClass();
                String string = sharedPreferences.getString("FBSDKFeature" + feature, null);
                if (string == null || !string.equals("18.0.3")) {
                    int i = feature.a;
                    EnumC1562q enumC1562qA = (i & 255) > 0 ? AbstractC1554i.a(i & (-256)) : (65280 & i) > 0 ? AbstractC1554i.a(i & (-65536)) : (16711680 & i) > 0 ? AbstractC1554i.a(i & (-16777216)) : AbstractC1554i.a(0);
                    if (enumC1562qA == feature) {
                        switch (feature.ordinal()) {
                            case 4:
                            case 5:
                            case 6:
                            case 7:
                            case 8:
                            case 9:
                            case 10:
                            case 11:
                            case 12:
                            case 13:
                            case 14:
                            case 15:
                            case 16:
                            case 17:
                            case 18:
                            case 19:
                            case 20:
                            case 21:
                            case EventType.WINDOW_STATE /* 22 */:
                            case EventType.AUDIO /* 23 */:
                            case EventType.VIDEO /* 24 */:
                            case EventType.SUBS /* 25 */:
                            case EventType.CDN /* 26 */:
                            case 27:
                            case 28:
                            case 29:
                            case 30:
                            case 31:
                            case 32:
                            case 33:
                            case 37:
                            case 38:
                            case 39:
                            case RequestError.NO_DEV_KEY /* 41 */:
                            case 42:
                            case 43:
                                break;
                            case 34:
                            case 35:
                            case 36:
                            case RequestError.NETWORK_FAILURE /* 40 */:
                            default:
                                z2 = true;
                                break;
                        }
                        return u.b("FBSDKFeature" + feature, com.facebook.o.b(), z2);
                    }
                    if (b(enumC1562qA)) {
                        switch (feature.ordinal()) {
                            case 4:
                            case 5:
                            case 6:
                            case 7:
                            case 8:
                            case 9:
                            case 10:
                            case 11:
                            case 12:
                            case 13:
                            case 14:
                            case 15:
                            case 16:
                            case 17:
                            case 18:
                            case 19:
                            case 20:
                            case 21:
                            case EventType.WINDOW_STATE /* 22 */:
                            case EventType.AUDIO /* 23 */:
                            case EventType.VIDEO /* 24 */:
                            case EventType.SUBS /* 25 */:
                            case EventType.CDN /* 26 */:
                            case 27:
                            case 28:
                            case 29:
                            case 30:
                            case 31:
                            case 32:
                            case 33:
                            case 37:
                            case 38:
                            case 39:
                            case RequestError.NO_DEV_KEY /* 41 */:
                            case 42:
                            case 43:
                                z = false;
                                break;
                            case 34:
                            case 35:
                            case 36:
                            case RequestError.NETWORK_FAILURE /* 40 */:
                            default:
                                z = true;
                                break;
                        }
                        if (u.b("FBSDKFeature" + feature, com.facebook.o.b(), z)) {
                        }
                    }
                }
            }
            return true;
        }
        return false;
    }
}
