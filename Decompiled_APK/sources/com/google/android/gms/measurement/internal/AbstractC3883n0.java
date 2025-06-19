package com.google.android.gms.measurement.internal;

import android.content.Context;
import android.content.res.Resources;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.text.TextUtils;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.ads.C1719Ka;
import com.j256.ormlite.field.FieldType;
import com.quizlet.quizletandroid.R;
import java.io.File;

/* renamed from: com.google.android.gms.measurement.internal.n0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3883n0 {
    public static final String[] a = {"ad_activeview", "ad_click", "ad_exposure", "ad_query", "ad_reward", "adunit_exposure", "app_clear_data", "app_exception", "app_remove", "app_store_refund", "app_store_subscription_cancel", "app_store_subscription_convert", "app_store_subscription_renew", "app_upgrade", "app_update", "ga_campaign", "error", "first_open", "first_visit", "in_app_purchase", "notification_dismiss", "notification_foreground", "notification_open", "notification_receive", "os_update", "session_start", "session_start_with_rollout", "user_engagement", "ad_impression", "screen_view", "ga_extra_parameter", "app_background", "firebase_campaign"};
    public static final String[] b = {"ad_impression"};
    public static final String[] c = {"_aa", "_ac", "_xa", "_aq", "_ar", "_xu", "_cd", "_ae", "_ui", "app_store_refund", "app_store_subscription_cancel", "app_store_subscription_convert", "app_store_subscription_renew", "_ug", "_au", "_cmp", "_err", "_f", "_v", "_iap", "_nd", "_nf", "_no", "_nr", "_ou", "_s", "_ssr", "_e", "_ai", "_vs", "_ep", "_ab", "_cmp"};
    public static final String[] d = {"purchase", "refund", "add_payment_info", "add_shipping_info", "add_to_cart", "add_to_wishlist", "begin_checkout", "remove_from_cart", "select_item", "select_promotion", "view_cart", "view_item", "view_item_list", "view_promotion", "ecommerce_purchase", "purchase_refund", "set_checkout_option", "checkout_progress", "select_content", "view_search_results"};
    public static final String[] e = {"ga_conversion", "engagement_time_msec", "exposure_time", "ad_event_id", "ad_unit_id", "ga_error", "ga_error_value", "ga_error_length", "ga_event_origin", "ga_screen", "ga_screen_class", "ga_screen_id", "ga_previous_screen", "ga_previous_class", "ga_previous_id", "manual_tracking", "message_device_time", "message_id", "message_name", "message_time", "message_tracking_id", "message_type", "previous_app_version", "previous_os_version", "topic", "update_with_analytics", "previous_first_open_count", "system_app", "system_app_update", "previous_install_count", "ga_event_id", "ga_extra_params_ct", "ga_group_name", "ga_list_length", "ga_index", "ga_event_name", "campaign_info_source", "cached_campaign", "deferred_analytics_collection", "ga_session_number", "ga_session_id", "campaign_extra_referrer", "app_in_background", "firebase_feature_rollouts", "customer_buyer_stage", "firebase_conversion", "firebase_error", "firebase_error_value", "firebase_error_length", "firebase_event_origin", "firebase_screen", "firebase_screen_class", "firebase_screen_id", "firebase_previous_screen", "firebase_previous_class", "firebase_previous_id", "session_number", "session_id"};
    public static final String[] f = {"_c", "_et", "_xt", "_aeid", "_ai", "_err", "_ev", "_el", "_o", "_sn", "_sc", "_si", "_pn", "_pc", "_pi", "_mst", "_ndt", "_nmid", "_nmn", "_nmt", "_nmtid", "_nmc", "_pv", "_po", "_nt", "_uwa", "_pfo", "_sys", "_sysu", "_pin", "_eid", "_epc", "_gn", "_ll", "_i", "_en", "_cis", "_cc", "_dac", "_sno", "_sid", "_cer", "_aib", "_ffr", "_cbs", "_c", "_err", "_ev", "_el", "_o", "_sn", "_sc", "_si", "_pn", "_pc", "_pi", "_sno", "_sid"};
    public static final String[] g = {"items"};
    public static final String[] h = {"affiliation", "coupon", "creative_name", "creative_slot", "currency", "_cbs", "discount", "index", "item_id", "item_brand", "item_category", "item_category2", "item_category3", "item_category4", "item_category5", "item_list_name", "item_list_id", "item_name", "item_variant", "location_id", "payment_type", "price", "promotion_id", "promotion_name", "quantity", "shipping", "shipping_tier", "tax", "transaction_id", "value", "item_list", "checkout_step", "checkout_option", "item_location_id"};
    public static final String[] i = {"firebase_last_notification", "first_open_time", "first_visit_time", "last_deep_link_referrer", "user_id", "last_advertising_id_reset", "first_open_after_install", "lifetime_user_engagement", "session_user_engagement", "non_personalized_ads", "ga_session_number", "ga_session_id", "last_gclid", "session_number", "session_id"};
    public static final String[] j = {"_ln", "_fot", "_fvt", "_ldl", FieldType.FOREIGN_ID_FIELD_SUFFIX, "_lair", "_fi", "_lte", "_se", "_npa", "_sno", "_sid", "_lgclid", "_sno", "_sid"};
    public static com.google.android.material.shape.e k;

    public static Object a(Bundle bundle, String str, Class cls, Object obj) {
        Object obj2 = bundle.get(str);
        if (obj2 == null) {
            return obj;
        }
        if (cls.isAssignableFrom(obj2.getClass())) {
            return obj2;
        }
        String canonicalName = cls.getCanonicalName();
        throw new IllegalStateException(android.support.v4.media.session.a.t(AbstractC0147y.h("Invalid conditional user property field type. '", str, "' expected [", canonicalName, "] but was ["), obj2.getClass().getCanonicalName(), "]"));
    }

    public static String b(Context context) {
        try {
            return context.getResources().getResourcePackageName(R.string.common_google_play_services_unknown_issue);
        } catch (Resources.NotFoundException unused) {
            return context.getPackageName();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0076 A[Catch: SQLiteException -> 0x00a0, TryCatch #1 {SQLiteException -> 0x00a0, blocks: (B:22:0x0045, B:24:0x0066, B:26:0x0076, B:28:0x007e, B:29:0x0081, B:30:0x009f, B:34:0x00a5, B:36:0x00a8, B:38:0x00b0, B:39:0x00b7, B:40:0x00ba, B:42:0x00c0, B:45:0x00cf, B:46:0x00d3, B:23:0x005f), top: B:54:0x0045, inners: #3 }] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00a5 A[Catch: SQLiteException -> 0x00a0, LOOP:1: B:34:0x00a5->B:39:0x00b7, LOOP_START, PHI: r5
  0x00a5: PHI (r5v5 int) = (r5v4 int), (r5v6 int) binds: [B:33:0x00a3, B:39:0x00b7] A[DONT_GENERATE, DONT_INLINE], TryCatch #1 {SQLiteException -> 0x00a0, blocks: (B:22:0x0045, B:24:0x0066, B:26:0x0076, B:28:0x007e, B:29:0x0081, B:30:0x009f, B:34:0x00a5, B:36:0x00a8, B:38:0x00b0, B:39:0x00b7, B:40:0x00ba, B:42:0x00c0, B:45:0x00cf, B:46:0x00d3, B:23:0x005f), top: B:54:0x0045, inners: #3 }] */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00c0 A[Catch: SQLiteException -> 0x00a0, TryCatch #1 {SQLiteException -> 0x00a0, blocks: (B:22:0x0045, B:24:0x0066, B:26:0x0076, B:28:0x007e, B:29:0x0081, B:30:0x009f, B:34:0x00a5, B:36:0x00a8, B:38:0x00b0, B:39:0x00b7, B:40:0x00ba, B:42:0x00c0, B:45:0x00cf, B:46:0x00d3, B:23:0x005f), top: B:54:0x0045, inners: #3 }] */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00de  */
    /* JADX WARN: Removed duplicated region for block: B:67:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:68:? A[SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r3v0 */
    /* JADX WARN: Type inference failed for: r3v1, types: [android.database.Cursor] */
    /* JADX WARN: Type inference failed for: r3v2 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void c(com.google.android.gms.measurement.internal.I r12, android.database.sqlite.SQLiteDatabase r13, java.lang.String r14, java.lang.String r15, java.lang.String r16, java.lang.String[] r17) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 234
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.AbstractC3883n0.c(com.google.android.gms.measurement.internal.I, android.database.sqlite.SQLiteDatabase, java.lang.String, java.lang.String, java.lang.String, java.lang.String[]):void");
    }

    public static String d(String str, String[] strArr, String[] strArr2) {
        int iMin = Math.min(strArr.length, strArr2.length);
        for (int i2 = 0; i2 < iMin; i2++) {
            String str2 = strArr[i2];
            if ((str == null && str2 == null) || (str != null && str.equals(str2))) {
                return strArr2[i2];
            }
        }
        return null;
    }

    public static void e(Bundle bundle, Object obj) {
        if (obj instanceof Double) {
            bundle.putDouble("value", ((Double) obj).doubleValue());
        } else if (obj instanceof Long) {
            bundle.putLong("value", ((Long) obj).longValue());
        } else {
            bundle.putString("value", obj.toString());
        }
    }

    public static void f(I i2, SQLiteDatabase sQLiteDatabase) {
        if (i2 == null) {
            throw new IllegalArgumentException("Monitor must not be null");
        }
        File file = new File(sQLiteDatabase.getPath());
        boolean readable = file.setReadable(false, false);
        C1719Ka c1719Ka = i2.j;
        if (!readable) {
            c1719Ka.f("Failed to turn off database read permission");
        }
        if (!file.setWritable(false, false)) {
            c1719Ka.f("Failed to turn off database write permission");
        }
        if (!file.setReadable(true, true)) {
            c1719Ka.f("Failed to turn on database read permission for owner");
        }
        if (file.setWritable(true, true)) {
            return;
        }
        c1719Ka.f("Failed to turn on database write permission for owner");
    }

    public static String g(Context context, String str) {
        com.google.android.gms.common.internal.u.h(context);
        Resources resources = context.getResources();
        if (TextUtils.isEmpty(str)) {
            str = b(context);
        }
        int identifier = resources.getIdentifier("google_app_id", "string", str);
        if (identifier == 0) {
            return null;
        }
        try {
            return resources.getString(identifier);
        } catch (Resources.NotFoundException unused) {
            return null;
        }
    }
}
