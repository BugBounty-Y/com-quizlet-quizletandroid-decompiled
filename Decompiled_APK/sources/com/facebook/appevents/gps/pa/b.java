package com.facebook.appevents.gps.pa;

import android.adservices.common.AdData;
import android.adservices.common.AdSelectionSignals;
import android.adservices.common.AdTechIdentifier;
import android.adservices.customaudience.CustomAudience;
import android.adservices.customaudience.CustomAudienceManager;
import android.adservices.customaudience.JoinCustomAudienceRequest;
import android.adservices.customaudience.TrustedBiddingData;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import com.facebook.o;
import java.util.concurrent.Executors;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class b {
    public static final b a = new b();
    public static final String b = "Fledge: ".concat(b.class.getSimpleName());
    public static boolean c;
    public static boolean d;
    public static CustomAudienceManager e;
    public static com.facebook.appevents.gps.a f;
    public static String g;

    public static final void a() {
        String string;
        if (com.facebook.internal.instrument.crashshield.a.b(b.class)) {
            return;
        }
        try {
            d = true;
            Context contextA = o.a();
            f = new com.facebook.appevents.gps.a(contextA);
            g = "https://www." + o.q + "/privacy_sandbox/pa/logic";
            try {
                CustomAudienceManager customAudienceManager = CustomAudienceManager.get(contextA);
                e = customAudienceManager;
                if (customAudienceManager != null) {
                    c = true;
                }
                string = null;
            } catch (Error e2) {
                string = e2.toString();
                Log.w(b, "Failed to get CustomAudienceManager: " + e2);
            } catch (Exception e3) {
                string = e3.toString();
                Log.w(b, "Failed to get CustomAudienceManager: " + e3);
            }
            if (c) {
                return;
            }
            com.facebook.appevents.gps.a aVar = f;
            if (aVar == null) {
                Intrinsics.m("gpsDebugLogger");
                throw null;
            }
            Bundle bundle = new Bundle();
            bundle.putString("gps_pa_failed_reason", string);
            Unit unit = Unit.a;
            aVar.a(bundle, "gps_pa_failed");
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(b.class, th);
        }
    }

    public final void b(String str, String str2) {
        String str3 = b;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            String strC = c(str, str2);
            if (strC == null) {
                return;
            }
            try {
                com.facebook.appevents.gps.ara.b bVar = new com.facebook.appevents.gps.ara.b(1);
                a.r();
                AdData.Builder builderA = a.a();
                String str4 = g;
                if (str4 == null) {
                    Intrinsics.m("baseUri");
                    throw null;
                }
                Uri uri = Uri.parse(str4.concat("/ad"));
                Intrinsics.c(uri, "Uri.parse(this)");
                AdData adDataBuild = builderA.setRenderUri(uri).setMetadata("{'isRealAd': false}").build();
                Intrinsics.checkNotNullExpressionValue(adDataBuild, "Builder()\n              …\n                .build()");
                a.x();
                TrustedBiddingData.Builder builderM = a.m();
                String str5 = g;
                if (str5 == null) {
                    Intrinsics.m("baseUri");
                    throw null;
                }
                Uri uri2 = Uri.parse(str5.concat("?trusted_bidding"));
                Intrinsics.c(uri2, "Uri.parse(this)");
                TrustedBiddingData trustedBiddingDataBuild = builderM.setTrustedBiddingUri(uri2).setTrustedBiddingKeys(A.b("")).build();
                Intrinsics.checkNotNullExpressionValue(trustedBiddingDataBuild, "Builder()\n              …\n                .build()");
                a.y();
                CustomAudience.Builder buyer = a.c().setName(strC).setBuyer(AdTechIdentifier.fromString("facebook.com"));
                StringBuilder sb = new StringBuilder();
                String str6 = g;
                if (str6 == null) {
                    Intrinsics.m("baseUri");
                    throw null;
                }
                sb.append(str6);
                sb.append("?daily&app_id=");
                sb.append(str);
                Uri uri3 = Uri.parse(sb.toString());
                Intrinsics.c(uri3, "Uri.parse(this)");
                CustomAudience.Builder dailyUpdateUri = buyer.setDailyUpdateUri(uri3);
                String str7 = g;
                if (str7 == null) {
                    Intrinsics.m("baseUri");
                    throw null;
                }
                Uri uri4 = Uri.parse(str7.concat("?bidding"));
                Intrinsics.c(uri4, "Uri.parse(this)");
                CustomAudience customAudienceBuild = dailyUpdateUri.setBiddingLogicUri(uri4).setTrustedBiddingData(trustedBiddingDataBuild).setUserBiddingSignals(AdSelectionSignals.fromString("{}")).setAds(A.b(adDataBuild)).build();
                Intrinsics.checkNotNullExpressionValue(customAudienceBuild, "Builder()\n              …(listOf(dummyAd)).build()");
                a.z();
                JoinCustomAudienceRequest joinCustomAudienceRequestBuild = a.j().setCustomAudience(customAudienceBuild).build();
                Intrinsics.checkNotNullExpressionValue(joinCustomAudienceRequestBuild, "Builder().setCustomAudience(ca).build()");
                CustomAudienceManager customAudienceManager = e;
                if (customAudienceManager != null) {
                    customAudienceManager.joinCustomAudience(joinCustomAudienceRequestBuild, Executors.newSingleThreadExecutor(), bVar);
                }
            } catch (Error e2) {
                Log.w(str3, "Failed to join Custom Audience: " + e2);
                com.facebook.appevents.gps.a aVar = f;
                if (aVar == null) {
                    Intrinsics.m("gpsDebugLogger");
                    throw null;
                }
                Bundle bundle = new Bundle();
                bundle.putString("gps_pa_failed_reason", e2.toString());
                Unit unit = Unit.a;
                aVar.a(bundle, "gps_pa_failed");
            } catch (Exception e3) {
                Log.w(str3, "Failed to join Custom Audience: " + e3);
                com.facebook.appevents.gps.a aVar2 = f;
                if (aVar2 == null) {
                    Intrinsics.m("gpsDebugLogger");
                    throw null;
                }
                Bundle bundle2 = new Bundle();
                bundle2.putString("gps_pa_failed_reason", e3.toString());
                Unit unit2 = Unit.a;
                aVar2.a(bundle2, "gps_pa_failed");
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final String c(String str, String str2) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this) && str2 != null) {
            try {
                if (!str2.equals("_removed_") && !StringsKt.G(str2, "gps", false)) {
                    return str + '@' + str2 + '@' + (System.currentTimeMillis() / 1000) + "@1";
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }
}
