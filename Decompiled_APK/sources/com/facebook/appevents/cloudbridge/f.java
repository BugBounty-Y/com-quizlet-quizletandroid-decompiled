package com.facebook.appevents.cloudbridge;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.facebook.internal.A;
import com.facebook.internal.J;
import com.facebook.y;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract class f {
    public static final Object a;
    public static final Object b;
    public static final Object c;

    static {
        b bVar = b.ANON_ID;
        k kVar = k.a;
        Pair pair = new Pair(bVar, new e(kVar, 1));
        Pair pair2 = new Pair(b.APP_USER_ID, new e(kVar, 2));
        Pair pair3 = new Pair(b.ADVERTISER_ID, new e(kVar, 3));
        Pair pair4 = new Pair(b.PAGE_ID, new e(kVar, 4));
        Pair pair5 = new Pair(b.PAGE_SCOPED_USER_ID, new e(kVar, 5));
        b bVar2 = b.ADV_TE;
        k kVar2 = k.b;
        a = V.f(pair, pair2, pair3, pair4, pair5, new Pair(bVar2, new e(kVar2, 7)), new Pair(b.APP_TE, new e(kVar2, 8)), new Pair(b.CONSIDER_VIEWS, new e(kVar2, 9)), new Pair(b.DEVICE_TOKEN, new e(kVar2, 10)), new Pair(b.EXT_INFO, new e(kVar2, 11)), new Pair(b.INCLUDE_DWELL_DATA, new e(kVar2, 12)), new Pair(b.INCLUDE_VIDEO_DATA, new e(kVar2, 13)), new Pair(b.INSTALL_REFERRER, new e(kVar2, 14)), new Pair(b.INSTALLER_PACKAGE, new e(kVar2, 15)), new Pair(b.RECEIPT_DATA, new e(kVar2, 16)), new Pair(b.URL_SCHEMES, new e(kVar2, 17)), new Pair(b.USER_DATA, new e(kVar, 0)));
        Pair pair6 = new Pair(l.EVENT_TIME, new d(null, i.EVENT_TIME));
        Pair pair7 = new Pair(l.EVENT_NAME, new d(null, i.EVENT_NAME));
        l lVar = l.VALUE_TO_SUM;
        k kVar3 = k.c;
        b = V.f(pair6, pair7, new Pair(lVar, new d(kVar3, i.VALUE_TO_SUM)), new Pair(l.CONTENT_IDS, new d(kVar3, i.CONTENT_IDS)), new Pair(l.CONTENTS, new d(kVar3, i.CONTENTS)), new Pair(l.CONTENT_TYPE, new d(kVar3, i.CONTENT_TYPE)), new Pair(l.CURRENCY, new d(kVar3, i.CURRENCY)), new Pair(l.DESCRIPTION, new d(kVar3, i.DESCRIPTION)), new Pair(l.LEVEL, new d(kVar3, i.LEVEL)), new Pair(l.MAX_RATING_VALUE, new d(kVar3, i.MAX_RATING_VALUE)), new Pair(l.NUM_ITEMS, new d(kVar3, i.NUM_ITEMS)), new Pair(l.PAYMENT_INFO_AVAILABLE, new d(kVar3, i.PAYMENT_INFO_AVAILABLE)), new Pair(l.REGISTRATION_METHOD, new d(kVar3, i.REGISTRATION_METHOD)), new Pair(l.SEARCH_STRING, new d(kVar3, i.SEARCH_STRING)), new Pair(l.SUCCESS, new d(kVar3, i.SUCCESS)), new Pair(l.ORDER_ID, new d(kVar3, i.ORDER_ID)), new Pair(l.AD_TYPE, new d(kVar3, i.AD_TYPE)));
        c = V.f(new Pair("fb_mobile_achievement_unlocked", j.UNLOCKED_ACHIEVEMENT), new Pair("fb_mobile_activate_app", j.ACTIVATED_APP), new Pair("fb_mobile_add_payment_info", j.ADDED_PAYMENT_INFO), new Pair("fb_mobile_add_to_cart", j.ADDED_TO_CART), new Pair("fb_mobile_add_to_wishlist", j.ADDED_TO_WISHLIST), new Pair("fb_mobile_complete_registration", j.COMPLETED_REGISTRATION), new Pair("fb_mobile_content_view", j.VIEWED_CONTENT), new Pair("fb_mobile_initiated_checkout", j.INITIATED_CHECKOUT), new Pair("fb_mobile_level_achieved", j.ACHIEVED_LEVEL), new Pair("fb_mobile_purchase", j.PURCHASED), new Pair("fb_mobile_rate", j.RATED), new Pair("fb_mobile_search", j.SEARCHED), new Pair("fb_mobile_spent_credits", j.SPENT_CREDITS), new Pair("fb_mobile_tutorial_completion", j.COMPLETED_TUTORIAL));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v4, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r1v7, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r1v8, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r1v9, types: [java.util.HashMap] */
    public static final Object a(Object value, String rawValue) {
        Intrinsics.checkNotNullParameter(rawValue, "field");
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(rawValue, "rawValue");
        int i = (Intrinsics.b(rawValue, "extInfo") || Intrinsics.b(rawValue, "url_schemes") || Intrinsics.b(rawValue, "fb_content_id") || Intrinsics.b(rawValue, "fb_content") || Intrinsics.b(rawValue, "data_processing_options")) ? 1 : (Intrinsics.b(rawValue, "advertiser_tracking_enabled") || Intrinsics.b(rawValue, "application_tracking_enabled")) ? 2 : Intrinsics.b(rawValue, "_logTime") ? 3 : 0;
        String str = value instanceof String ? (String) value : null;
        if (i == 0 || str == null) {
            return value;
        }
        int iK = AbstractC0147y.k(i);
        if (iK != 0) {
            if (iK != 1) {
                if (iK == 2) {
                    return StringsKt.toIntOrNull(value.toString());
                }
                throw new NoWhenBranchMatchedException();
            }
            Integer intOrNull = StringsKt.toIntOrNull(str.toString());
            if (intOrNull != null) {
                return Boolean.valueOf(intOrNull.intValue() != 0);
            }
            return null;
        }
        try {
            ArrayList arrayListG = J.g(new JSONArray(str));
            ArrayList arrayList = new ArrayList();
            Iterator it2 = arrayListG.iterator();
            while (it2.hasNext()) {
                ?? G = (String) it2.next();
                try {
                    try {
                        G = J.h(new JSONObject((String) G));
                    } catch (JSONException unused) {
                        G = J.g(new JSONArray((String) G));
                    }
                } catch (JSONException unused2) {
                }
                arrayList.add(G);
            }
            return arrayList;
        } catch (JSONException e) {
            com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
            com.google.mlkit.common.sdkinternal.model.a.w(y.d, "AppEventsConversionsAPITransformer", "\n transformEvents JSONException: \n%s\n%s", value, e);
            return Unit.a;
        }
    }
}
