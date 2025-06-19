package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.text.TextUtils;
import com.google.ads.mediation.AbstractAdViewAdapter;
import com.google.android.gms.ads.formats.AdManagerAdViewOptions;
import com.google.android.gms.ads.formats.PublisherAdViewOptions;
import com.google.android.gms.ads.internal.client.zzm;
import java.util.ArrayList;
import java.util.Iterator;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.dn, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1977dn implements InterfaceC2751vm {
    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final boolean a(C1849aq c1849aq, Vp vp) {
        return !TextUtils.isEmpty(vp.v.optString(AbstractAdViewAdapter.AD_UNIT_ID_PARAMETER, ""));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final com.google.common.util.concurrent.e b(C1849aq c1849aq, Vp vp) {
        JSONObject jSONObject = vp.v;
        String strOptString = jSONObject.optString(AbstractAdViewAdapter.AD_UNIT_ID_PARAMETER, "");
        C2023eq c2023eq = (C2023eq) c1849aq.a.b;
        C1979dq c1979dq = new C1979dq();
        c1979dq.o.b = c2023eq.o.b;
        zzm zzmVar = c2023eq.d;
        c1979dq.a = zzmVar;
        c1979dq.b = c2023eq.e;
        c1979dq.u = c2023eq.t;
        String str = c2023eq.f;
        c1979dq.c = str;
        c1979dq.d = c2023eq.a;
        c1979dq.f = c2023eq.g;
        c1979dq.g = c2023eq.h;
        c1979dq.h = c2023eq.i;
        c1979dq.i = c2023eq.j;
        AdManagerAdViewOptions adManagerAdViewOptions = c2023eq.l;
        c1979dq.j = adManagerAdViewOptions;
        if (adManagerAdViewOptions != null) {
            c1979dq.e = adManagerAdViewOptions.a;
        }
        PublisherAdViewOptions publisherAdViewOptions = c2023eq.m;
        c1979dq.k = publisherAdViewOptions;
        if (publisherAdViewOptions != null) {
            c1979dq.e = publisherAdViewOptions.a;
            c1979dq.l = publisherAdViewOptions.b;
        }
        c1979dq.p = c2023eq.p;
        c1979dq.q = c2023eq.q;
        c1979dq.r = c2023eq.c;
        c1979dq.s = c2023eq.r;
        c1979dq.t = c2023eq.s;
        c1979dq.c = strOptString;
        Bundle bundle = zzmVar.m;
        Bundle bundle2 = bundle == null ? new Bundle() : new Bundle(bundle);
        Bundle bundle3 = bundle2.getBundle("com.google.ads.mediation.admob.AdMobAdapter");
        Bundle bundle4 = bundle3 == null ? new Bundle() : new Bundle(bundle3);
        bundle4.putInt("gw", 1);
        String strOptString2 = jSONObject.optString("mad_hac", null);
        if (strOptString2 != null) {
            bundle4.putString("mad_hac", strOptString2);
        }
        String strOptString3 = jSONObject.optString("adJson", null);
        if (strOptString3 != null) {
            bundle4.putString("_ad", strOptString3);
        }
        bundle4.putBoolean("_noRefresh", true);
        JSONObject jSONObject2 = vp.D;
        Iterator<String> itKeys = jSONObject2.keys();
        while (itKeys.hasNext()) {
            String next = itKeys.next();
            String strOptString4 = jSONObject2.optString(next, null);
            if (next != null) {
                bundle4.putString(next, strOptString4);
            }
        }
        bundle2.putBundle("com.google.ads.mediation.admob.AdMobAdapter", bundle4);
        c1979dq.a = new zzm(zzmVar.a, zzmVar.b, bundle4, zzmVar.d, zzmVar.e, zzmVar.f, zzmVar.g, zzmVar.h, zzmVar.i, zzmVar.j, zzmVar.k, zzmVar.l, bundle2, zzmVar.n, zzmVar.o, zzmVar.p, zzmVar.q, zzmVar.r, zzmVar.s, zzmVar.t, zzmVar.u, zzmVar.v, zzmVar.w, zzmVar.x, zzmVar.y, zzmVar.z);
        C2023eq c2023eqA = c1979dq.a();
        Bundle bundle5 = new Bundle();
        androidx.work.impl.model.n nVar = c1849aq.b;
        Bundle bundle6 = new Bundle();
        Xp xp = (Xp) nVar.b;
        bundle6.putStringArrayList("nofill_urls", new ArrayList<>(xp.a));
        bundle6.putInt("refresh_interval", xp.c);
        bundle6.putString("gws_query_id", xp.b);
        bundle5.putBundle("parent_common_config", bundle6);
        Bundle bundle7 = new Bundle();
        bundle7.putString("initial_ad_unit_id", str);
        bundle7.putString("allocation_id", vp.w);
        bundle7.putString("ad_source_name", vp.F);
        bundle7.putStringArrayList("click_urls", new ArrayList<>(vp.c));
        bundle7.putStringArrayList("imp_urls", new ArrayList<>(vp.d));
        bundle7.putStringArrayList("manual_tracking_urls", new ArrayList<>(vp.p));
        bundle7.putStringArrayList("fill_urls", new ArrayList<>(vp.m));
        bundle7.putStringArrayList("video_start_urls", new ArrayList<>(vp.g));
        bundle7.putStringArrayList("video_reward_urls", new ArrayList<>(vp.h));
        bundle7.putStringArrayList("video_complete_urls", new ArrayList<>(vp.i));
        bundle7.putString("transaction_id", vp.j);
        bundle7.putString("valid_from_timestamp", vp.k);
        bundle7.putBoolean("is_closable_area_disabled", vp.P);
        bundle7.putString("recursive_server_response_data", vp.o0);
        bundle7.putBoolean("is_analytics_logging_enabled", vp.W);
        zzbwj zzbwjVar = vp.l;
        if (zzbwjVar != null) {
            Bundle bundle8 = new Bundle();
            bundle8.putInt("rb_amount", zzbwjVar.b);
            bundle8.putString("rb_type", zzbwjVar.a);
            bundle7.putParcelableArray("rewards", new Bundle[]{bundle8});
        }
        bundle5.putBundle("parent_ad_config", bundle7);
        return c(c2023eqA, bundle5, vp, c1849aq);
    }

    public abstract Iq c(C2023eq c2023eq, Bundle bundle, Vp vp, C1849aq c1849aq);
}
