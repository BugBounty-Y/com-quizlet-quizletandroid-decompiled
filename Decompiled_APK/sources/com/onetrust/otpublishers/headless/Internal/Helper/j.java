package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTBroadcastServiceKeys;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class j {
    public final Context a;
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d b;
    public final com.onetrust.otpublishers.headless.Internal.Preferences.e c;
    public final com.onetrust.otpublishers.headless.Internal.Models.b d;
    public JSONArray f;
    public JSONArray g;
    public boolean h;
    public final com.quizlet.shared.usecase.srs.a i = new com.quizlet.shared.usecase.srs.a(21);
    public boolean e = false;

    public j(@NonNull Context context) {
        this.a = context;
        this.b = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
        this.c = new com.onetrust.otpublishers.headless.Internal.Preferences.e(context);
        this.d = new com.onetrust.otpublishers.headless.Internal.Models.b(context);
    }

    public static JSONArray a(JSONArray jSONArray, List list) {
        ArrayList arrayList = new ArrayList();
        try {
            JSONArray jSONArray2 = new JSONArray();
            for (int i = 0; i < jSONArray.length(); i++) {
                try {
                    androidx.work.impl.model.l.h(i, jSONArray, jSONArray2, new JSONObject());
                } catch (JSONException e) {
                    OTLogger.c("OTSDKListFilter", 6, "Error on parsing Categories list. Error msg = " + e.getMessage());
                }
            }
            for (int i2 = 0; i2 < jSONArray2.length(); i2++) {
                if (jSONArray2.getJSONObject(i2).has("CustomGroupId")) {
                    arrayList.add(jSONArray2.getJSONObject(i2).getString("CustomGroupId"));
                }
            }
        } catch (JSONException e2) {
            Z.o("error while computing all categories e:", e2, "OTData");
        }
        if (list.isEmpty()) {
            list = arrayList;
        }
        JSONArray jSONArray3 = new JSONArray();
        for (int i3 = 0; i3 < list.size(); i3++) {
            try {
                f(jSONArray, jSONArray3, ((String) list.get(i3)).trim());
            } catch (JSONException e3) {
                Z.p("Error on parsing SDK list. Error msg = ", e3, "OTData", 6);
            }
        }
        OTLogger.c("ContentValues", 3, "getSDKList Final: " + jSONArray3);
        return jSONArray3;
    }

    public static void b(String str, JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        if (jSONObject2.has(str)) {
            try {
                jSONObject.put(str, jSONObject2.getBoolean(str));
            } catch (JSONException e) {
                T.d(e, android.support.v4.media.session.a.y("Error in appending pc boolean data. key = ", str, "Error message : "), "OTData", 6);
            }
        }
    }

    public static void d(JSONArray jSONArray, JSONArray jSONArray2) throws JSONException {
        for (int i = 0; i < jSONArray2.length(); i++) {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("Name", jSONArray2.getJSONObject(i).getString("Name"));
            jSONObject.put("SdkId", jSONArray2.getJSONObject(i).getString("SdkId"));
            jSONObject.put("Description", jSONArray2.getJSONObject(i).getString("Description"));
            jSONArray.put(jSONObject);
        }
    }

    public static void f(JSONArray jSONArray, JSONArray jSONArray2, String str) throws JSONException {
        for (int i = 0; i < jSONArray.length(); i++) {
            JSONArray jSONArray3 = jSONArray.getJSONObject(i).getJSONArray("FirstPartyCookies");
            String strOptString = jSONArray.getJSONObject(i).optString("CustomGroupId", "");
            JSONObject jSONObject = jSONArray.getJSONObject(i);
            if (strOptString.equals(str)) {
                d(jSONArray2, jSONArray3);
                if (!jSONObject.has("SubGroups") || jSONObject.optBoolean("ShowSubgroup")) {
                    return;
                }
                for (int i2 = 0; i2 < jSONObject.getJSONArray("SubGroups").length(); i2++) {
                    d(jSONArray2, jSONObject.getJSONArray("SubGroups").getJSONObject(i2).getJSONArray("FirstPartyCookies"));
                }
                return;
            }
            if (jSONObject.has("SubGroups") && !retrofit2.adapter.rxjava3.d.l(jSONObject.getJSONArray("SubGroups"))) {
                for (int i3 = 0; i3 < jSONObject.getJSONArray("SubGroups").length(); i3++) {
                    JSONObject jSONObject2 = jSONObject.getJSONArray("SubGroups").getJSONObject(i3);
                    if (str.equalsIgnoreCase(jSONObject2.optString("CustomGroupId", ""))) {
                        d(jSONArray2, jSONObject2.getJSONArray("FirstPartyCookies"));
                    }
                }
            }
        }
    }

    public static void g(JSONArray jSONArray, JSONArray jSONArray2, JSONObject jSONObject, OTPublishersHeadlessSDK oTPublishersHeadlessSDK, int i, JSONObject jSONObject2, JSONArray jSONArray3) throws JSONException {
        String strF;
        if (com.onetrust.otpublishers.headless.Internal.a.j(jSONArray2.getJSONObject(i).optString("PurposeId"))) {
            strF = android.support.v4.media.session.a.f(i, "OT_PURPOSE_ID_");
        } else {
            jSONObject2.put("Id", jSONArray2.getJSONObject(i).optString("PurposeId"));
            jSONObject2.put("TransactionType", oTPublishersHeadlessSDK.getConsentStatusForGroupId(jSONArray2.getJSONObject(i).optString("CustomGroupId"), jSONArray2.getJSONObject(i).getString("Status")) == 0 ? "NOTGIVEN" : "CONFIRMED");
            jSONArray.put(jSONObject2);
            strF = jSONArray2.getJSONObject(i).optString("PurposeId");
            JSONObject jSONObject3 = new JSONObject();
            jSONObject3.put("Id", jSONArray2.getJSONObject(i).optString("PurposeId"));
            jSONObject3.put("TransactionType", jSONArray2.getJSONObject(i).getString("Status").equals("inactive") ? "NOTGIVEN" : "CONFIRMED");
            jSONArray3.put(jSONObject3);
        }
        jSONObject.put(strF, jSONArray2.getJSONObject(i).optString("CustomGroupId", ""));
    }

    public static void j(JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        if (jSONObject2.has("IsIabEnabled") && jSONObject2.has("IabType")) {
            jSONObject.put("IsIabEnabled", jSONObject2.getBoolean("IsIabEnabled"));
            jSONObject.put("IabType", jSONObject2.getString("IabType"));
            if (!jSONObject2.getBoolean("IsIabEnabled") || "".equals(jSONObject2.getString("IabType"))) {
                return;
            }
            r("BannerDPDTitle", jSONObject, jSONObject2);
            if (!jSONObject2.has("BannerDPDDescription") || jSONObject2.isNull("BannerDPDDescription")) {
                return;
            }
            jSONObject.put("BannerDPDDescription", jSONObject2.get("BannerDPDDescription").toString());
        }
    }

    public static boolean l(SharedPreferences sharedPreferences, JSONObject jSONObject, boolean z, JSONObject jSONObject2, String str) {
        if (str == null) {
            return z;
        }
        String strOptString = jSONObject2.optString(str.toLowerCase(Locale.ROOT));
        OTLogger.c("OTData", 3, android.support.v4.media.session.a.m("hasGrpConfigChanged: group type - ", strOptString, "group -", str));
        if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString) || "BRANCH".equalsIgnoreCase(strOptString) || strOptString.equalsIgnoreCase("IAB2_STACK") || strOptString.equalsIgnoreCase("IAB2V2_STACK") || jSONObject.has(str) || z) {
            return z;
        }
        assistantMode.refactored.a.p(sharedPreferences, "OT_HAS_GROUP_CONFIG_CHANGED", true);
        return true;
    }

    public static boolean n(JSONObject jSONObject) throws JSONException {
        if (!jSONObject.has("profile")) {
            return false;
        }
        JSONObject jSONObject2 = jSONObject.getJSONObject("profile");
        if (!jSONObject2.has("sync")) {
            return false;
        }
        JSONObject jSONObject3 = jSONObject2.getJSONObject("sync");
        if (jSONObject3.has("shouldShowBannerAsConsentExpired")) {
            return jSONObject3.getBoolean("shouldShowBannerAsConsentExpired");
        }
        return false;
    }

    public static void r(String str, JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        if (jSONObject2.has(str)) {
            try {
                jSONObject.put(str, jSONObject2.getString(str));
            } catch (JSONException e) {
                T.d(e, android.support.v4.media.session.a.y("Error in appending pc data key. key = ", str, "Error message : "), "OTData", 6);
            }
        }
    }

    public static void u(JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        r("PcTextColor", jSONObject, jSONObject2);
        r("PcButtonColor", jSONObject, jSONObject2);
        r("PcButtonColor", jSONObject, jSONObject2);
        r("PcButtonTextColor", jSONObject, jSONObject2);
        r("PcBackgroundColor", jSONObject, jSONObject2);
        r("PcMenuColor", jSONObject, jSONObject2);
        r("PcMenuHighLightColor", jSONObject, jSONObject2);
        r("PcLinksTextColor", jSONObject, jSONObject2);
        r("OptanonLogo", jSONObject, jSONObject2);
        b("ShowCookieList", jSONObject, jSONObject2);
        b("PCShowCookieHost", jSONObject, jSONObject2);
        b("PCShowCookieDuration", jSONObject, jSONObject2);
        b("PCShowCookieType", jSONObject, jSONObject2);
        b("PCShowCookieCategory", jSONObject, jSONObject2);
        r("BConsentText", jSONObject, jSONObject2);
        r("BLegitInterestText", jSONObject, jSONObject2);
        if (jSONObject2.has("PCShowCookieDescription") && !jSONObject2.isNull("PCShowCookieDescription")) {
            jSONObject.put("PCShowCookieDescription", jSONObject2.get("PCShowCookieDescription").toString());
        }
        r("AllowHostOptOut", jSONObject, jSONObject2);
        r("IabLegalTextUrl", jSONObject, jSONObject2);
        jSONObject.put("BConsentPurposesText", jSONObject2.optString("BConsentPurposesText", ""));
        jSONObject.put("BLegitimateInterestPurposesText", jSONObject2.optString("BLegitimateInterestPurposesText", ""));
        jSONObject.put("BSpecialFeaturesText", jSONObject2.optString("BSpecialFeaturesText", ""));
        jSONObject.put("BSpecialPurposesText", jSONObject2.optString("BSpecialPurposesText", ""));
        jSONObject.put("BFeaturesText", jSONObject2.optString("BFeaturesText", ""));
    }

    public static void y(JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        r("MainText", jSONObject, jSONObject2);
        r("MainInfoText", jSONObject, jSONObject2);
        r("AboutText", jSONObject, jSONObject2);
        r("AboutLink", jSONObject, jSONObject2);
        r("AlwaysActiveText", jSONObject, jSONObject2);
        r("VendorLevelOptOut", jSONObject, jSONObject2);
        r("PreferenceCenterPosition", jSONObject, jSONObject2);
        r("PreferenceCenterConfirmText", jSONObject, jSONObject2);
        r("VendorListText", jSONObject, jSONObject2);
        r("PCGrpDescLinkPosition", jSONObject, jSONObject2);
        r("ThirdPartyCookieListText", jSONObject, jSONObject2);
        r("PreferenceCenterManagePreferencesText", jSONObject, jSONObject2);
        b("ShowPreferenceCenterCloseButton", jSONObject, jSONObject2);
        r("CloseText", jSONObject, jSONObject2);
        r("AddLinksToCookiepedia", jSONObject, jSONObject2);
        r("CookieListEnabled", jSONObject, jSONObject2);
        r("Center", jSONObject, jSONObject2);
        r("Panel", jSONObject, jSONObject2);
        r("Popup", jSONObject, jSONObject2);
        r("List", jSONObject, jSONObject2);
        r("Tab", jSONObject, jSONObject2);
        r("PCFirstPartyCookieListText", jSONObject, jSONObject2);
        r("PCViewCookiesText", jSONObject, jSONObject2);
        r("PCenterBackText", jSONObject, jSONObject2);
        r("PCenterVendorsListText", jSONObject, jSONObject2);
        r("PCIABVendorsText", jSONObject, jSONObject2);
        r("PCenterViewPrivacyPolicyText", jSONObject, jSONObject2);
        r("PCenterClearFiltersText", jSONObject, jSONObject2);
        r("PCenterApplyFiltersText", jSONObject, jSONObject2);
        r("PCenterAllowAllConsentText", jSONObject, jSONObject2);
        r("PCenterRejectAllButtonText", jSONObject, jSONObject2);
        b("PCenterShowRejectAllButton", jSONObject, jSONObject2);
        r("ConfirmText", jSONObject, jSONObject2);
        r("PCenterCookiesListText", jSONObject, jSONObject2);
        r("PCenterCancelFiltersText", jSONObject, jSONObject2);
        b("PCenterEnableAccordion", jSONObject, jSONObject2);
        b("IsIabEnabled", jSONObject, jSONObject2);
        r("PCGrpDescType", jSONObject, jSONObject2);
        r("PCVendorFullLegalText", jSONObject, jSONObject2);
        r("IabType", jSONObject, jSONObject2);
        r("PCenterVendorListDescText", jSONObject, jSONObject2);
        r("PCPrivacyLinkActionAriaLabel", jSONObject, jSONObject2);
        r("PCLogoScreenReader", jSONObject, jSONObject2);
        r("PCDSIDCopyAriaLabel", jSONObject, jSONObject2);
        r("CloseText", jSONObject, jSONObject2);
        r("PCenterVendorListSearch", jSONObject, jSONObject2);
        r("PCenterCookieListSearch", jSONObject, jSONObject2);
        r("PCenterVendorListFilterAria", jSONObject, jSONObject2);
        r("PCenterCookieListFilterAria", jSONObject, jSONObject2);
        r("PCVendorListFilterUnselectedAriaLabel", jSONObject, jSONObject2);
        r("PCVendorListFilterSelectedAriaLabel", jSONObject, jSONObject2);
        r("PCIllusText", jSONObject, jSONObject2);
        jSONObject.put("PCenterViewPrivacyPolicyText", jSONObject2.optString("PCenterViewPrivacyPolicyText", ""));
        jSONObject.put("PCenterVendorListLifespan", jSONObject2.optString("PCenterVendorListLifespan", ""));
        jSONObject.put("PCenterVendorListDisclosure", jSONObject2.optString("PCenterVendorListDisclosure", ""));
        jSONObject.put("PCenterVendorListNonCookieUsage", jSONObject2.optString("PCenterVendorListNonCookieUsage", ""));
        jSONObject.put("PCenterVendorListLifespanDay", jSONObject2.optString("PCenterVendorListLifespanDay", ""));
        jSONObject.put("PCenterVendorListLifespanDays", jSONObject2.optString("PCenterVendorListLifespanDays", ""));
        jSONObject.put("PCenterVendorListLifespanMonth", jSONObject2.optString("PCenterVendorListLifespanMonth", ""));
        jSONObject.put("PCenterVendorListLifespanMonths", jSONObject2.optString("PCenterVendorListLifespanMonths", ""));
        jSONObject.put("PCenterVendorListStorageIdentifier", jSONObject2.optString("PCenterVendorListStorageIdentifier", ""));
        jSONObject.put("PCenterVendorListStorageType", jSONObject2.optString("PCenterVendorListStorageType", ""));
        jSONObject.put("PCenterVendorListStorageDomain", jSONObject2.optString("PCenterVendorListStorageDomain", ""));
        jSONObject.put("PCenterVendorListStoragePurposes", jSONObject2.optString("PCenterVendorListStoragePurposes", ""));
        jSONObject.put("UseGoogleVendors", jSONObject2.optBoolean("UseGoogleVendors", false));
        jSONObject.put("PCVLSDomainsUsed", jSONObject2.optString("PCVLSDomainsUsed", ""));
        jSONObject.put("PCVLSUse", jSONObject2.optString("PCVLSUse", ""));
        jSONObject.put("PCVListDataDeclarationText", jSONObject2.optString("PCVListDataDeclarationText", ""));
        jSONObject.put("PCVListDataRetentionText", jSONObject2.optString("PCVListDataRetentionText", ""));
        jSONObject.put("PCVListStdRetentionText", jSONObject2.optString("PCVListStdRetentionText", ""));
        jSONObject.put("PCIABVendorLegIntClaimText", jSONObject2.optString("PCIABVendorLegIntClaimText", ""));
        jSONObject.put("SDKLanguageCode", c.w(jSONObject2));
        jSONObject.put("PCVendorsCountText", jSONObject2.optString("PCVendorsCountText", ""));
        jSONObject.put("PCVendorsCountFeatureText", jSONObject2.optString("PCVendorsCountFeatureText", ""));
        jSONObject.put("PCVendorsCountSpcFeatureText", jSONObject2.optString("PCVendorsCountSpcFeatureText", ""));
        jSONObject.put("PCVendorsCountSpcPurposeText", jSONObject2.optString("PCVendorsCountSpcPurposeText", ""));
    }

    /* JADX WARN: Removed duplicated region for block: B:87:0x0243  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void A(org.json.JSONObject r24) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 619
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.j.A(org.json.JSONObject):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0070 A[Catch: Exception -> 0x004d, TRY_LEAVE, TryCatch #1 {Exception -> 0x004d, blocks: (B:17:0x003b, B:19:0x0047, B:26:0x006a, B:28:0x0070, B:25:0x0065, B:24:0x0050), top: B:40:0x003b, outer: #0, inners: #2 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(java.lang.String r7, boolean r8) {
        /*
            r6 = this;
            java.lang.String r0 = "OneTrust"
            android.content.Context r1 = r6.a
            if (r8 == 0) goto Lb2
            r8 = 6
            org.json.JSONObject r2 = new org.json.JSONObject     // Catch: org.json.JSONException -> L33
            r2.<init>(r7)     // Catch: org.json.JSONException -> L33
            boolean r7 = n(r2)     // Catch: org.json.JSONException -> L33
            if (r7 == 0) goto Lb2
            java.lang.String r7 = "com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER"
            r2 = 0
            android.content.SharedPreferences r7 = r1.getSharedPreferences(r7, r2)     // Catch: org.json.JSONException -> L33
            com.onetrust.otpublishers.headless.Internal.profile.c r3 = new com.onetrust.otpublishers.headless.Internal.profile.c     // Catch: org.json.JSONException -> L33
            r3.<init>(r1)     // Catch: org.json.JSONException -> L33
            boolean r3 = r3.t()     // Catch: org.json.JSONException -> L33
            java.lang.String r4 = ""
            if (r3 == 0) goto L36
            java.lang.String r3 = "OT_ACTIVE_PROFILE_ID"
            java.lang.String r3 = r7.getString(r3, r4)     // Catch: org.json.JSONException -> L33
            com.onetrust.otpublishers.headless.Internal.Preferences.f r5 = new com.onetrust.otpublishers.headless.Internal.Preferences.f     // Catch: org.json.JSONException -> L33
            r5.<init>(r1, r7, r3)     // Catch: org.json.JSONException -> L33
            r3 = 1
            goto L38
        L33:
            r7 = move-exception
            goto Lab
        L36:
            r5 = 0
            r3 = r2
        L38:
            if (r3 == 0) goto L3b
            r7 = r5
        L3b:
            java.lang.String r3 = "OTT_CULTURE_DOMAIN_DATA"
            java.lang.String r7 = r7.getString(r3, r4)     // Catch: java.lang.Exception -> L4d
            boolean r3 = com.onetrust.otpublishers.headless.Internal.a.j(r7)     // Catch: java.lang.Exception -> L4d
            if (r3 != 0) goto L65
            org.json.JSONObject r3 = new org.json.JSONObject     // Catch: java.lang.Exception -> L4d org.json.JSONException -> L4f
            r3.<init>(r7)     // Catch: java.lang.Exception -> L4d org.json.JSONException -> L4f
            goto L6a
        L4d:
            r7 = move-exception
            goto L75
        L4f:
            r7 = move-exception
            java.lang.StringBuilder r3 = new java.lang.StringBuilder     // Catch: java.lang.Exception -> L4d
            java.lang.String r5 = "error while returning culture domain data, err: "
            r3.<init>(r5)     // Catch: java.lang.Exception -> L4d
            java.lang.String r7 = r7.getMessage()     // Catch: java.lang.Exception -> L4d
            r3.append(r7)     // Catch: java.lang.Exception -> L4d
            java.lang.String r7 = r3.toString()     // Catch: java.lang.Exception -> L4d
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r8, r7)     // Catch: java.lang.Exception -> L4d
        L65:
            org.json.JSONObject r3 = new org.json.JSONObject     // Catch: java.lang.Exception -> L4d
            r3.<init>()     // Catch: java.lang.Exception -> L4d
        L6a:
            int r7 = r3.length()     // Catch: java.lang.Exception -> L4d
            if (r7 <= 0) goto L8b
            java.lang.String r4 = r3.toString()     // Catch: java.lang.Exception -> L4d
            goto L8b
        L75:
            java.lang.StringBuilder r3 = new java.lang.StringBuilder     // Catch: org.json.JSONException -> L33
            java.lang.String r5 = "empty data as SDK not yet initialized "
            r3.<init>(r5)     // Catch: org.json.JSONException -> L33
            java.lang.String r7 = r7.getMessage()     // Catch: org.json.JSONException -> L33
            r3.append(r7)     // Catch: org.json.JSONException -> L33
            java.lang.String r7 = r3.toString()     // Catch: org.json.JSONException -> L33
            r3 = 3
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r3, r7)     // Catch: org.json.JSONException -> L33
        L8b:
            boolean r7 = com.onetrust.otpublishers.headless.Internal.a.j(r4)     // Catch: org.json.JSONException -> L33
            if (r7 == 0) goto L92
            goto Lb2
        L92:
            org.json.JSONObject r7 = new org.json.JSONObject     // Catch: org.json.JSONException -> L33
            r7.<init>(r4)     // Catch: org.json.JSONException -> L33
            com.onetrust.otpublishers.headless.Internal.Helper.j r0 = new com.onetrust.otpublishers.headless.Internal.Helper.j     // Catch: org.json.JSONException -> L33
            r0.<init>(r1)     // Catch: org.json.JSONException -> L33
            java.lang.String r1 = "Groups"
            org.json.JSONArray r7 = r7.getJSONArray(r1)     // Catch: org.json.JSONException -> L33
            org.json.JSONObject r1 = new org.json.JSONObject     // Catch: org.json.JSONException -> L33
            r1.<init>()     // Catch: org.json.JSONException -> L33
            r0.i(r7, r1, r2)     // Catch: org.json.JSONException -> L33
            goto Lb2
        Lab:
            java.lang.String r0 = "Error on cleanUpIabIfPurposeIfConsentExpired, error: "
            java.lang.String r1 = "OTData"
            com.google.android.gms.measurement.internal.Z.p(r0, r7, r1, r8)
        Lb2:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.j.c(java.lang.String, boolean):void");
    }

    public final void e(JSONArray jSONArray, JSONArray jSONArray2, int i) throws JSONException {
        JSONObject jSONObject = jSONArray2.getJSONObject(i);
        if (jSONObject.has("SubGroups")) {
            if (jSONObject.getBoolean("ShowInPopup")) {
                jSONArray.put(jSONObject);
                return;
            }
            return;
        }
        JSONObject jSONObject2 = jSONArray2.getJSONObject(i);
        if (jSONObject2.getString("Type").equals("COOKIE") && jSONObject2.getString("Parent").isEmpty()) {
            if (jSONObject2.getJSONArray("FirstPartyCookies").length() <= 0) {
                return;
            }
        } else if (!jSONObject2.getBoolean("IsIabPurpose") || !jSONObject2.getString("Parent").isEmpty() || !jSONObject2.getBoolean("ShowInPopup") || !com.quizlet.shared.usecase.srs.a.q(jSONObject2, this.h)) {
            return;
        }
        jSONArray.put(jSONObject2);
    }

    public final void h(JSONArray jSONArray, JSONObject jSONObject, JSONObject jSONObject2, JSONObject jSONObject3) throws JSONException {
        jSONObject.getJSONObject("consentPayload").put("purposes", jSONArray);
        jSONObject2.getJSONObject("consentPayload").put("purposes", jSONArray);
        SharedPreferences.Editor editorEdit = this.b.b().edit();
        editorEdit.putString("OTT_CONSENT_LOG_DATA", jSONObject.toString());
        editorEdit.putString("OT_CL_DEFAULT_PAYLOAD", jSONObject2.toString());
        editorEdit.putString("OTT_INTERNAL_PURPOSE_GROUP_MAP", jSONObject3.toString());
        editorEdit.apply();
    }

    public final void i(JSONArray jSONArray, JSONObject jSONObject, boolean z) {
        try {
            JSONObject jSONObject2 = new JSONObject(this.b.b().getString("OTT_CONSENT_STATUS", "{}"));
            if (!z) {
                p();
                jSONObject = jSONObject2;
            }
            if (jSONArray.length() > 0) {
                s(jSONArray, jSONObject, z);
            }
        } catch (Exception e) {
            Z.n("error while clearing IAB values on re-consent, err : ", e, "OTData", 6);
        }
        OTLogger.c("GoogleVendorHelper", 3, "Resetting user consent on Google vendor list.");
        Context context = this.a;
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
        String string = dVar.b().getString("OT_GOOGLE_GVL_COMPLETE_OBJECT", null);
        JSONObject jSONObject3 = new JSONObject();
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return;
        }
        try {
            jSONObject3 = new JSONObject(string);
        } catch (JSONException e2) {
            Z.p("Error on parsing google vendors on clearUserConsent, error = ", e2, "GoogleVendorHelper", 6);
        }
        a.a(context, dVar, new JSONObject(), jSONObject3);
    }

    public final void k(JSONObject jSONObject, JSONObject jSONObject2, JSONArray jSONArray, JSONArray jSONArray2, JSONObject jSONObject3, boolean z, JSONObject jSONObject4) throws JSONException {
        if (jSONObject3.has("CustomGroupId")) {
            String string = jSONObject3.getString("CustomGroupId");
            if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                return;
            }
            jSONObject.put(string.toLowerCase(Locale.ENGLISH), -1);
            if (jSONObject3.getString("Status").contains("always")) {
                jSONObject4.put(string, jSONObject3.getString("Status"));
            }
            if (jSONObject3.has("SubGroups")) {
                JSONArray jSONArray3 = jSONObject3.getJSONArray("SubGroups");
                for (int i = 0; i < jSONArray3.length(); i++) {
                    JSONObject jSONObject5 = jSONArray3.getJSONObject(i);
                    if (jSONObject5.has("CustomGroupId")) {
                        String string2 = jSONObject5.getString("CustomGroupId");
                        jSONObject.put(string2.toLowerCase(Locale.ENGLISH), -1);
                        if (jSONObject5.getString("Status").contains("always")) {
                            jSONObject4.put(string2, jSONObject5.getString("Status"));
                        }
                    }
                }
            }
            if (z && jSONObject3.optString("Parent").isEmpty() && jSONObject3.getJSONArray("FirstPartyCookies").length() == 0 && !com.onetrust.otpublishers.headless.Internal.a.j(jSONObject3.optString("PurposeId"))) {
                JSONObject jSONObject6 = new JSONObject();
                String strOptString = jSONObject3.optString("PurposeId");
                String str = jSONObject3.optString("Status").contains("always") ? "NO_CHOICE" : new OTPublishersHeadlessSDK(this.a).getConsentStatusForGroupId(jSONObject3.optString("CustomGroupId"), jSONObject3.optString("Status")) == 0 ? "NOTGIVEN" : "CONFIRMED";
                if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                    return;
                }
                for (int i2 = 0; i2 < jSONArray.length(); i2++) {
                    JSONObject jSONObject7 = jSONArray.getJSONObject(i2);
                    if (jSONObject7.has("Id") && strOptString.equalsIgnoreCase(jSONObject7.getString("Id"))) {
                        return;
                    }
                }
                if (com.quizlet.shared.usecase.srs.a.q(jSONObject3, this.h)) {
                    jSONObject6.put("Id", strOptString);
                    jSONObject6.put("TransactionType", str);
                    if (!jSONObject3.optString("Status").contains("always")) {
                        jSONObject2.put(jSONObject3.optString("PurposeId"), string);
                    }
                    jSONArray.put(jSONObject6);
                    jSONArray2.put(jSONObject6);
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:187:0x05b9 A[Catch: JSONException -> 0x0597, TryCatch #22 {JSONException -> 0x0597, blocks: (B:176:0x0562, B:185:0x059f, B:187:0x05b9, B:189:0x05bf, B:191:0x05e1, B:196:0x05f9, B:198:0x060a, B:200:0x0612, B:193:0x05e8, B:195:0x05ee, B:184:0x059a, B:181:0x057f, B:178:0x0578), top: B:371:0x0562, inners: #5 }] */
    /* JADX WARN: Removed duplicated region for block: B:189:0x05bf A[Catch: JSONException -> 0x0597, TryCatch #22 {JSONException -> 0x0597, blocks: (B:176:0x0562, B:185:0x059f, B:187:0x05b9, B:189:0x05bf, B:191:0x05e1, B:196:0x05f9, B:198:0x060a, B:200:0x0612, B:193:0x05e8, B:195:0x05ee, B:184:0x059a, B:181:0x057f, B:178:0x0578), top: B:371:0x0562, inners: #5 }] */
    /* JADX WARN: Removed duplicated region for block: B:239:0x0733  */
    /* JADX WARN: Removed duplicated region for block: B:341:0x0378 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:343:0x026b A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:363:0x03c7 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:68:0x01e5  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x028d A[Catch: JSONException -> 0x028a, TryCatch #24 {JSONException -> 0x028a, blocks: (B:88:0x024f, B:97:0x0292, B:99:0x0365, B:100:0x0370, B:106:0x0396, B:105:0x0381, B:96:0x028d, B:93:0x0272, B:102:0x0378, B:90:0x026b), top: B:372:0x024f, inners: #6, #7 }] */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0365 A[Catch: JSONException -> 0x028a, TryCatch #24 {JSONException -> 0x028a, blocks: (B:88:0x024f, B:97:0x0292, B:99:0x0365, B:100:0x0370, B:106:0x0396, B:105:0x0381, B:96:0x028d, B:93:0x0272, B:102:0x0378, B:90:0x026b), top: B:372:0x024f, inners: #6, #7 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m(java.lang.String r18, com.onetrust.otpublishers.headless.Public.OTCallback r19, com.onetrust.otpublishers.headless.Public.Response.OTResponse r20, com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r21, boolean r22) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 2397
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.j.m(java.lang.String, com.onetrust.otpublishers.headless.Public.OTCallback, com.onetrust.otpublishers.headless.Public.Response.OTResponse, com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK, boolean):boolean");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Can't wrap try/catch for region: R(20:4|(9:6|(1:8)(1:10)|9|11|(1:17)(1:15)|16|18|(2:(1:22)|23)(2:(1:26)|27)|28)(1:30)|29|31|(1:36)(1:35)|37|(2:39|(10:41|(2:42|(5:442|44|(5:46|432|47|(1:49)(1:52)|53)(1:55)|54|59)(1:444))|60|(4:63|(3:445|65|(3:448|74|452)(5:449|69|(1:71)(1:73)|72|453))(1:451)|450|61)|446|75|(1:77)(1:79)|78|80|(2:81|(8:83|(1:92)(8:87|(1:89)|90|91|169|(5:171|(1:177)(1:175)|176|178|(1:186))(1:188)|187|189)|93|(2:90|91)(2:95|(3:97|90|91)(5:98|99|125|130|(3:132|(2:134|(2:161|(2:165|(1:167))(1:164))(10:137|(1:139)(1:140)|141|(1:143)(1:145)|144|146|(3:149|(1:151)(1:152)|153)|154|(1:158)|159))(1:168)|160)(1:91)))|169|(0)(0)|187|189)(19:454|190|(1:192)(1:193)|(1:195)|196|(1:198)|199|200|204|(3:206|(18:208|(1:210)|211|(2:214|212)|455|215|(1:217)(1:218)|219|(10:222|(1:231)(7:226|(0)(1:230)|244|246|(4:249|(2:254|458)(2:253|459)|255|247)|457|256)|232|(7:242|(1:245)|244|246|(1:247)|457|256)(1:234)|235|246|(1:247)|457|256|220)|456|257|(2:259|(1:263))|264|(4:266|(1:268)(1:269)|270|(5:272|(2:274|(9:276|(5:278|(1:280)(1:281)|(1:283)|284|(4:286|(1:288)(1:289)|(1:291)|292))(1:294)|293|295|(1:297)|298|(1:300)|303|(17:305|(1:307)(1:308)|309|(1:311)(1:312)|313|(5:316|(2:318|(2:320|(4:322|(2:324|(2:326|(2:328|(1:330)(3:331|(1:333)(1:334)|(1:343)(1:342)))(1:335))(1:336))(1:337)|338|(2:340|343)(0))(1:345))(0))(0)|344|346|314)|460|347|(2:349|(2:351|(1:353)))|354|(4:356|(7:359|(1:372)(2:368|(1:370)(1:371))|373|(1:381)(1:379)|380|382|357)|461|383)(1:384)|385|(1:387)(1:388)|389|438|390|391)(0))(0))(1:301)|302|303|(0)(0))(0))(1:394)|436|395|(1:397)|401)(1:403)|402)(1:404)|405|(1:407)(6:409|440|410|(1:412)|413|416)|408|419|434|420|(1:424)|428|429)))(1:201))(1:203)|202|200|204|(0)(0)|405|(0)(0)|408|419|434|420|(2:422|424)|428|429) */
    /* JADX WARN: Code restructure failed: missing block: B:426:0x0c83, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:427:0x0c84, code lost:
    
        com.google.android.gms.measurement.internal.Z.p("error while formatting groups with err = ", r0, "AppDataParser", 6);
     */
    /* JADX WARN: Removed duplicated region for block: B:100:0x0363  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x04d8  */
    /* JADX WARN: Removed duplicated region for block: B:188:0x0563  */
    /* JADX WARN: Removed duplicated region for block: B:206:0x0690  */
    /* JADX WARN: Removed duplicated region for block: B:249:0x079c  */
    /* JADX WARN: Removed duplicated region for block: B:294:0x0931  */
    /* JADX WARN: Removed duplicated region for block: B:301:0x0967  */
    /* JADX WARN: Removed duplicated region for block: B:305:0x0976  */
    /* JADX WARN: Removed duplicated region for block: B:312:0x0995  */
    /* JADX WARN: Removed duplicated region for block: B:343:0x0a6a  */
    /* JADX WARN: Removed duplicated region for block: B:345:0x0a73  */
    /* JADX WARN: Removed duplicated region for block: B:404:0x0bcc  */
    /* JADX WARN: Removed duplicated region for block: B:407:0x0be5  */
    /* JADX WARN: Removed duplicated region for block: B:409:0x0c02  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean o(org.json.JSONObject r75, boolean r76) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 3274
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.j.o(org.json.JSONObject, boolean):boolean");
    }

    public final void p() throws JSONException {
        JSONObject jSONObject;
        JSONArray jSONArrayNames;
        JSONObject jSONObject2;
        JSONArray jSONArrayNames2;
        JSONObject jSONObject3;
        JSONArray jSONArrayNames3;
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.b;
        String string = dVar.b().getString("OTT_IAB_CONSENTABLE_PURPOSES", "");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return;
        }
        try {
            JSONObject jSONObject4 = new JSONObject(string);
            if (jSONObject4.has("purposes") && (jSONArrayNames3 = (jSONObject3 = jSONObject4.getJSONObject("purposes")).names()) != null) {
                for (int i = 0; i < jSONObject3.length(); i++) {
                    jSONObject3.put(jSONArrayNames3.getString(i), 0);
                }
                jSONObject4.put("purposes", jSONObject3);
            }
            if (jSONObject4.has("purposeLegitimateInterests") && (jSONArrayNames2 = (jSONObject2 = jSONObject4.getJSONObject("purposeLegitimateInterests")).names()) != null) {
                for (int i2 = 0; i2 < jSONObject2.length(); i2++) {
                    jSONObject2.put(jSONArrayNames2.getString(i2), 1);
                }
                jSONObject4.put("purposeLegitimateInterests", jSONObject2);
            }
            if (jSONObject4.has("special_feature_opt_ins") && (jSONArrayNames = (jSONObject = jSONObject4.getJSONObject("special_feature_opt_ins")).names()) != null) {
                for (int i3 = 0; i3 < jSONObject.length(); i3++) {
                    jSONObject.put(jSONArrayNames.getString(i3), 0);
                }
                jSONObject4.put("special_feature_opt_ins", jSONObject);
            }
            dVar.b().edit().putString("OTT_IAB_CONSENTABLE_PURPOSES", jSONObject4.toString()).apply();
            OTLogger.c("OTData", 3, "iab related values cleared on auto re-consent");
        } catch (JSONException e) {
            Z.o("Error when setting IAB default values on auto reconsent,", e, "OTData");
        }
    }

    public final void q() throws JSONException {
        Context context = this.a;
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.b;
        String string = dVar.b().getString("OTT_CONSENT_STATUS", "");
        String string2 = dVar.b().getString("OTT_ALWAYS_ACTIVE_GROUPS", "");
        String string3 = dVar.b().getString("OT_INTERNAL_SDK_STATUS_MAP", "");
        try {
            JSONObject jSONObject = new JSONObject();
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                jSONObject = new JSONObject(string);
            }
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                JSONArray jSONArrayNames = new JSONObject(string2).names();
                if (!retrofit2.adapter.rxjava3.d.l(jSONArrayNames)) {
                    for (int i = 0; i < jSONArrayNames.length(); i++) {
                        jSONObject.put(jSONArrayNames.getString(i), 1);
                    }
                }
            }
            new o(context).c(jSONObject);
            if (com.onetrust.otpublishers.headless.Internal.a.j(string3)) {
                return;
            }
            JSONObject jSONObject2 = new JSONObject(string3);
            if (retrofit2.adapter.rxjava3.d.o(jSONObject2)) {
                return;
            }
            try {
                Iterator<String> itKeys = jSONObject2.keys();
                while (itKeys.hasNext()) {
                    String next = itKeys.next();
                    int i2 = jSONObject2.getInt(next);
                    if (2 == i2) {
                        i2 = 1;
                    }
                    OTLogger.c("OTConsentChanges", 4, "Sending " + next + " broadcast, value = " + i2);
                    Intent intent = new Intent(next);
                    intent.putExtra(OTBroadcastServiceKeys.EVENT_STATUS, i2);
                    intent.setPackage(context.getApplicationContext().getPackageName());
                    context.sendBroadcast(intent);
                }
            } catch (JSONException e) {
                OTLogger.c("OTConsentChanges", 6, "error in broadcasting SDK status. err = " + e.getMessage() + " changedConsents = " + jSONObject2.toString());
            }
        } catch (JSONException e2) {
            Z.p("error while broadcasting default consent values : ", e2, "OTData", 6);
        }
    }

    public final void s(JSONArray jSONArray, JSONObject jSONObject, boolean z) throws JSONException {
        for (int i = 0; i < jSONArray.length(); i++) {
            JSONObject jSONObject2 = jSONArray.getJSONObject(i);
            boolean zEquals = jSONObject2.getString("Status").equals("inactive");
            int i2 = !zEquals ? 1 : 0;
            String strOptString = jSONObject2.optString("Parent");
            if (jSONObject2.getBoolean("IsIabPurpose") && jSONObject2.getBoolean("ShowInPopup") && com.quizlet.shared.usecase.srs.a.q(jSONObject2, this.h)) {
                jSONObject.put(jSONObject2.optString("CustomGroupId"), i2);
                boolean zG = this.c.g(strOptString);
                if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString) && zEquals && !zG && !strOptString.startsWith("IABV2") && !strOptString.startsWith("IAB2V2") && !strOptString.startsWith("ISFV2") && !strOptString.startsWith("ISF2V2")) {
                    jSONObject.put(strOptString, i2);
                }
            }
        }
        if (z) {
            return;
        }
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.b;
        SharedPreferences.Editor editorEdit = dVar.b().edit();
        editorEdit.putString("OTT_CONSENT_STATUS", jSONObject.toString());
        String string = dVar.b().getString("OT_IAB_DEFAULT_AVL", "");
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            editorEdit.putString("OT_IAB_ACTIVE_VENDORLIST", string);
        }
        editorEdit.apply();
    }

    public final void t(JSONObject jSONObject) throws JSONException {
        JSONObject jSONObject2 = jSONObject.getJSONObject("culture");
        if (jSONObject2.has("MobileData")) {
            JSONObject jSONObject3 = jSONObject2.getJSONObject("MobileData");
            com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.b;
            this.i.getClass();
            String string = dVar.b().getString("OT_TEMPLATE_TYPE", "");
            String str = com.onetrust.otpublishers.headless.Internal.a.j(string) ? "" : string;
            if (("IAB2".equalsIgnoreCase(str) || "IAB2V2".equalsIgnoreCase(str)) && !jSONObject3.optJSONObject("ccpaData").optBoolean("computeCCPA")) {
                new p(this.a).d();
            }
        }
    }

    public final boolean v(String str, boolean z) {
        boolean zO = false;
        try {
            JSONObject jSONObject = new JSONObject(str);
            if (jSONObject.has("domain")) {
                String strOptString = jSONObject.getJSONObject("domain").getJSONObject("ruleDetails").optString(DBUserFields.Names.USER_UPGRADE_TYPE, "");
                com.quizlet.shared.usecase.srs.a aVar = this.i;
                com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.b;
                aVar.getClass();
                dVar.b().edit().putString("OT_TEMPLATE_TYPE", strOptString).apply();
                boolean zOptBoolean = jSONObject.getJSONObject("domain").optBoolean("AuthenticatedConsent");
                com.onetrust.otpublishers.headless.Internal.Preferences.e eVar = this.c;
                eVar.getClass();
                OTLogger.c("authenticatedConsentFlow", 3, "saveAuthenticatedConsentFlag = " + zOptBoolean);
                eVar.a.b().edit().putBoolean("OT_AUTHENTICATED_CONSENT_SERVER_FLAG", zOptBoolean).apply();
            }
            if (!jSONObject.has("culture")) {
                return false;
            }
            zO = o(jSONObject, z);
            t(jSONObject);
            return zO;
        } catch (JSONException e) {
            Z.p("error in formatting ott data with err = ", e, "OTData", 6);
            return zO;
        }
    }

    public final void w(String str, boolean z) {
        if (z) {
            try {
                if (n(new JSONObject(str))) {
                    return;
                }
                new d(this.a).e();
            } catch (JSONException e) {
                Z.p("Error while parsing ottWholeData, error = ", e, "OTData", 6);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x002c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void x(org.json.JSONObject r8) throws org.json.JSONException {
        /*
            r7 = this;
            android.content.Context r0 = r7.a
            java.lang.String r1 = "enableConsent"
            java.lang.String r2 = "general"
            java.lang.String r3 = "googleAd"
            java.lang.String r4 = "prompts"
            r5 = 0
            boolean r6 = r8.has(r4)     // Catch: org.json.JSONException -> L2a
            if (r6 == 0) goto L39
            org.json.JSONObject r8 = r8.getJSONObject(r4)     // Catch: org.json.JSONException -> L2a
            boolean r4 = r8.has(r3)     // Catch: org.json.JSONException -> L2a
            if (r4 == 0) goto L2c
            org.json.JSONObject r8 = r8.getJSONObject(r3)     // Catch: org.json.JSONException -> L2a
            boolean r3 = r8.has(r2)     // Catch: org.json.JSONException -> L2a
            if (r3 == 0) goto L2c
            org.json.JSONObject r8 = r8.getJSONObject(r2)     // Catch: org.json.JSONException -> L2a
            goto L2d
        L2a:
            r8 = move-exception
            goto L31
        L2c:
            r8 = r5
        L2d:
            if (r8 == 0) goto L39
            r5 = r8
            goto L39
        L31:
            java.lang.String r2 = "Error in  parse GoogleAddGeneralData , message = "
            java.lang.String r3 = "AppDataParser"
            r4 = 4
            com.google.android.gms.measurement.internal.Z.p(r2, r8, r3, r4)
        L39:
            if (r5 == 0) goto L6b
            boolean r8 = r5.has(r1)     // Catch: org.json.JSONException -> L62
            if (r8 == 0) goto L6b
            boolean r8 = r5.getBoolean(r1)     // Catch: org.json.JSONException -> L62
            if (r8 == 0) goto L6b
            boolean r8 = com.onetrust.otpublishers.headless.Internal.a.m(r0)     // Catch: org.json.JSONException -> L62
            if (r8 == 0) goto L6b
            com.quizlet.shared.usecase.studiableMetadata.a r8 = new com.quizlet.shared.usecase.studiableMetadata.a     // Catch: org.json.JSONException -> L62
            r1 = 21
            r8.<init>(r1)     // Catch: org.json.JSONException -> L62
            com.google.firebase.crashlytics.internal.common.i r1 = new com.google.firebase.crashlytics.internal.common.i     // Catch: org.json.JSONException -> L62
            r1.<init>(r8, r0, r5)     // Catch: org.json.JSONException -> L62
            java.lang.Thread r8 = new java.lang.Thread     // Catch: org.json.JSONException -> L62
            r8.<init>(r1)     // Catch: org.json.JSONException -> L62
            r8.start()     // Catch: org.json.JSONException -> L62
            goto L6b
        L62:
            r8 = move-exception
            java.lang.String r0 = "Error on checking google add consent logging state. Error = "
            java.lang.String r1 = "GoogleAdInfo"
            r2 = 6
            com.google.android.gms.measurement.internal.Z.p(r0, r8, r1, r2)
        L6b:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.j.x(org.json.JSONObject):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:46:0x00e6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void z(java.lang.String r18, boolean r19) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 440
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.j.z(java.lang.String, boolean):void");
    }
}
