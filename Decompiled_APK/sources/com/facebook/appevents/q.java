package com.facebook.appevents;

import com.facebook.FacebookException;
import com.google.android.gms.internal.mlkit_vision_common.H;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import kotlin.Pair;
import kotlin.collections.C4933y;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class q {
    public static final Map b;
    public final LinkedHashMap a = new LinkedHashMap();

    static {
        String[] elements = {"fb_iap_package_name", "fb_iap_subs_auto_renewing", "fb_free_trial_period", "fb_intro_price_amount_micros", "fb_intro_price_cycles", "fb_iap_base_plan", "is_implicit_purchase_logging_enabled", "fb_iap_sdk_supported_library_versions", "is_autolog_app_events_enabled", "fb_iap_client_library_version", "fb_iap_subs_period", "fb_iap_purchase_token", "fb_iap_non_deduped_event_time", "fb_iap_actual_dedup_result", "fb_iap_actual_dedup_key_used", "fb_iap_test_dedup_result", "fb_iap_test_dedup_key_used"};
        Intrinsics.checkNotNullParameter(elements, "elements");
        Set setT = C4933y.T(elements);
        String[] elements2 = {"fb_iap_product_id", "fb_iap_product_type", "fb_iap_purchase_time"};
        Intrinsics.checkNotNullParameter(elements2, "elements");
        b = U.b(new Pair(r.a, new Pair(setT, C4933y.T(elements2))));
    }

    public final void a(r type, String key, Object value) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        try {
            HashSet hashSet = e.f;
            H.a(key);
            if (!(value instanceof String) && !(value instanceof Number)) {
                String str = String.format("Parameter value '%s' for key '%s' should be a string or a numeric type.", Arrays.copyOf(new Object[]{value, key}, 2));
                Intrinsics.checkNotNullExpressionValue(str, "format(format, *args)");
                throw new FacebookException(str);
            }
            LinkedHashMap linkedHashMap = this.a;
            if (!linkedHashMap.containsKey(type)) {
                linkedHashMap.put(type, new LinkedHashMap());
            }
            Map map = (Map) linkedHashMap.get(type);
            if (map != null) {
                map.put(key, value);
            }
        } catch (Exception unused) {
        }
    }
}
