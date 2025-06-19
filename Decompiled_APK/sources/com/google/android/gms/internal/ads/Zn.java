package com.google.android.gms.internal.ads;

import android.location.Location;
import android.os.Bundle;
import android.text.TextUtils;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.ads.internal.client.zzm;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class Zn implements Uo {
    public final C2023eq a;
    public final long b;

    public Zn(C2023eq c2023eq, long j) {
        this.a = c2023eq;
        this.b = j;
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final void b(Object obj) {
        Bundle bundle = ((Og) obj).b;
        C2023eq c2023eq = this.a;
        bundle.putString("slotname", c2023eq.f);
        zzm zzmVar = c2023eq.d;
        if (zzmVar.f) {
            bundle.putBoolean("test_request", true);
        }
        int i = zzmVar.g;
        AbstractC2096gb.E(i, bundle, "tag_for_child_directed_treatment", i != -1);
        if (zzmVar.a >= 8) {
            int i2 = zzmVar.t;
            AbstractC2096gb.E(i2, bundle, "tag_for_under_age_of_consent", i2 != -1);
        }
        AbstractC2096gb.t(DTBMetricsConfiguration.APSMETRICS_URL, zzmVar.l, bundle);
        AbstractC2096gb.y(bundle, "neighboring_content_urls", zzmVar.v);
        Bundle bundle2 = zzmVar.c;
        Bundle bundle3 = (Bundle) bundle2.clone();
        HashSet hashSet = new HashSet(Arrays.asList(((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.z7)).split(",", -1)));
        for (String str : bundle2.keySet()) {
            if (!hashSet.contains(str)) {
                bundle3.remove(str);
            }
        }
        if (bundle3 != null) {
            bundle.putBundle("extras", bundle3);
        }
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final void c(Object obj) {
        Bundle bundle = ((Og) obj).a;
        C2023eq c2023eq = this.a;
        zzm zzmVar = c2023eq.d;
        bundle.putInt("http_timeout_millis", zzmVar.w);
        bundle.putString("slotname", c2023eq.f);
        int i = c2023eq.o.b;
        if (i == 0) {
            throw null;
        }
        int i2 = i - 1;
        if (i2 == 1) {
            bundle.putBoolean("is_new_rewarded", true);
        } else if (i2 == 2) {
            bundle.putBoolean("is_rewarded_interstitial", true);
        }
        bundle.putLong("start_signals_timestamp", this.b);
        Bundle bundle2 = zzmVar.c;
        AbstractC2096gb.K(bundle, "is_sdk_preload", true, bundle2.getBoolean("is_sdk_preload", false));
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd", Locale.US);
        long j = zzmVar.b;
        AbstractC2096gb.I(bundle, "cust_age", simpleDateFormat.format(new Date(j)), j != -1);
        if (bundle2 != null) {
            bundle.putBundle("extras", bundle2);
        }
        int i3 = zzmVar.d;
        AbstractC2096gb.E(i3, bundle, "cust_gender", i3 != -1);
        AbstractC2096gb.y(bundle, "kw", zzmVar.e);
        int i4 = zzmVar.g;
        AbstractC2096gb.E(i4, bundle, "tag_for_child_directed_treatment", i4 != -1);
        if (zzmVar.f) {
            bundle.putBoolean("test_request", true);
        }
        bundle.putInt("ppt_p13n", zzmVar.y);
        int i5 = zzmVar.a;
        AbstractC2096gb.E(1, bundle, "d_imp_hdr", i5 >= 2 && zzmVar.h);
        String str = zzmVar.i;
        AbstractC2096gb.I(bundle, "ppid", str, i5 >= 2 && !TextUtils.isEmpty(str));
        Location location = zzmVar.k;
        if (location != null) {
            float accuracy = location.getAccuracy() * 1000.0f;
            long time = location.getTime() * 1000;
            double latitude = location.getLatitude() * 1.0E7d;
            double longitude = 1.0E7d * location.getLongitude();
            Bundle bundle3 = new Bundle();
            bundle3.putFloat("radius", accuracy);
            bundle3.putLong("lat", (long) latitude);
            bundle3.putLong("long", (long) longitude);
            bundle3.putLong("time", time);
            bundle.putBundle("uule", bundle3);
        }
        AbstractC2096gb.t(DTBMetricsConfiguration.APSMETRICS_URL, zzmVar.l, bundle);
        AbstractC2096gb.y(bundle, "neighboring_content_urls", zzmVar.v);
        Bundle bundle4 = zzmVar.n;
        if (bundle4 != null) {
            bundle.putBundle("custom_targeting", bundle4);
        }
        AbstractC2096gb.y(bundle, "category_exclusions", zzmVar.o);
        AbstractC2096gb.t("request_agent", zzmVar.p, bundle);
        AbstractC2096gb.t("request_pkg", zzmVar.q, bundle);
        AbstractC2096gb.K(bundle, "is_designed_for_families", zzmVar.r, i5 >= 7);
        if (i5 >= 8) {
            int i6 = zzmVar.t;
            AbstractC2096gb.E(i6, bundle, "tag_for_under_age_of_consent", i6 != -1);
            AbstractC2096gb.t("max_ad_content_rating", zzmVar.u, bundle);
        }
    }
}
