package com.onetrust.otpublishers.headless.Public;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import assistantMode.utils.studiableMetadata.b;
import com.appsflyer.AdRevenueScheme;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3589c0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.V;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W;
import com.google.android.gms.internal.mlkit_vision_document_scanner.X;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Event.a;
import com.onetrust.otpublishers.headless.Internal.Helper.k;
import com.onetrust.otpublishers.headless.Internal.Helper.n;
import com.onetrust.otpublishers.headless.Internal.Helper.o;
import com.onetrust.otpublishers.headless.Internal.Helper.p;
import com.onetrust.otpublishers.headless.Internal.Helper.r;
import com.onetrust.otpublishers.headless.Internal.Helper.s;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Internal.Preferences.d;
import com.onetrust.otpublishers.headless.Internal.Preferences.e;
import com.onetrust.otpublishers.headless.Internal.Preferences.f;
import com.onetrust.otpublishers.headless.Internal.profile.c;
import com.onetrust.otpublishers.headless.Public.DataModel.OTCache;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.DataModel.OTGeolocationModel;
import com.onetrust.otpublishers.headless.Public.DataModel.OTRenameProfileParams;
import com.onetrust.otpublishers.headless.Public.DataModel.OTSdkParams;
import com.onetrust.otpublishers.headless.Public.DataModel.OTUXParams;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;
import com.onetrust.otpublishers.headless.Public.Response.OTResponseType;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import com.onetrust.otpublishers.headless.UI.TVUI.fragments.g;
import com.onetrust.otpublishers.headless.UI.fragment.C4063g;
import com.onetrust.otpublishers.headless.UI.fragment.D;
import com.onetrust.otpublishers.headless.UI.fragment.ViewOnClickListenerC4065i;
import com.onetrust.otpublishers.headless.UI.fragment.l;
import com.onetrust.otpublishers.headless.UI.fragment.m;
import com.onetrust.otpublishers.headless.UI.fragment.t;
import com.quizlet.quizletandroid.R;
import java.io.IOException;
import java.util.ArrayList;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class OTPublishersHeadlessSDK {
    public static final String VENDOR_DETAILS_ERROR_MSG = "Error in getting vendorDetails , error = ";
    public final Context a;
    public s b;
    public OTVendorUtils c;
    public k d;
    public String e;
    public String f;
    public final a g;

    public OTPublishersHeadlessSDK(@NonNull Context context) {
        Context applicationContext = context.getApplicationContext();
        this.a = applicationContext;
        this.b = new s(applicationContext);
        this.c = new OTVendorUtils(getVendorListData(), getVendorListData(OTVendorListMode.GOOGLE), getVendorListData(OTVendorListMode.GENERAL));
        this.g = new a();
        this.d = new k(applicationContext);
    }

    @Keep
    public static void enableOTSDKLog(int i) {
        OTLogger.a = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x005a A[Catch: Exception -> 0x0037, TRY_LEAVE, TryCatch #1 {Exception -> 0x0037, blocks: (B:9:0x0025, B:11:0x0031, B:18:0x0054, B:20:0x005a, B:17:0x004f, B:16:0x003a), top: B:30:0x0025, inners: #0 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(@androidx.annotation.NonNull androidx.fragment.app.I r7, com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration r8) {
        /*
            r6 = this;
            java.lang.String r0 = "OneTrust"
            android.content.Context r1 = r6.a
            java.lang.String r2 = "com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER"
            r3 = 0
            android.content.SharedPreferences r2 = r1.getSharedPreferences(r2, r3)
            boolean r4 = com.google.android.gms.internal.mlkit_vision_document_scanner.Q.a(r1)
            java.lang.String r5 = ""
            if (r4 == 0) goto L20
            java.lang.String r3 = "OT_ACTIVE_PROFILE_ID"
            java.lang.String r3 = r2.getString(r3, r5)
            com.onetrust.otpublishers.headless.Internal.Preferences.f r4 = new com.onetrust.otpublishers.headless.Internal.Preferences.f
            r4.<init>(r1, r2, r3)
            r3 = 1
            goto L21
        L20:
            r4 = 0
        L21:
            if (r3 == 0) goto L24
            r2 = r4
        L24:
            r1 = 6
            java.lang.String r3 = "OTT_CULTURE_DOMAIN_DATA"
            java.lang.String r2 = r2.getString(r3, r5)     // Catch: java.lang.Exception -> L37
            boolean r3 = com.onetrust.otpublishers.headless.Internal.a.j(r2)     // Catch: java.lang.Exception -> L37
            if (r3 != 0) goto L4f
            org.json.JSONObject r3 = new org.json.JSONObject     // Catch: java.lang.Exception -> L37 org.json.JSONException -> L39
            r3.<init>(r2)     // Catch: java.lang.Exception -> L37 org.json.JSONException -> L39
            goto L54
        L37:
            r2 = move-exception
            goto L5f
        L39:
            r2 = move-exception
            java.lang.StringBuilder r3 = new java.lang.StringBuilder     // Catch: java.lang.Exception -> L37
            java.lang.String r4 = "error while returning culture domain data, err: "
            r3.<init>(r4)     // Catch: java.lang.Exception -> L37
            java.lang.String r2 = r2.getMessage()     // Catch: java.lang.Exception -> L37
            r3.append(r2)     // Catch: java.lang.Exception -> L37
            java.lang.String r2 = r3.toString()     // Catch: java.lang.Exception -> L37
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r1, r2)     // Catch: java.lang.Exception -> L37
        L4f:
            org.json.JSONObject r3 = new org.json.JSONObject     // Catch: java.lang.Exception -> L37
            r3.<init>()     // Catch: java.lang.Exception -> L37
        L54:
            int r2 = r3.length()     // Catch: java.lang.Exception -> L37
            if (r2 <= 0) goto L65
            java.lang.String r5 = r3.toString()     // Catch: java.lang.Exception -> L37
            goto L65
        L5f:
            java.lang.String r3 = "empty data as SDK not yet initialized "
            r4 = 3
            com.google.android.gms.measurement.internal.Z.n(r3, r2, r0, r4)
        L65:
            boolean r2 = com.onetrust.otpublishers.headless.Internal.a.j(r5)
            if (r2 != 0) goto L7c
            com.onetrust.otpublishers.headless.Internal.Event.a r0 = r6.g
            com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReason r1 = new com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReason
            r2 = 110(0x6e, float:1.54E-43)
            java.lang.String r3 = com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReason.getResponseMessage(r2)
            r1.<init>(r2, r3)
            com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3621g0.e(r7, r0, r8, r1, r6)
            goto L88
        L7c:
            android.content.Context r7 = r6.a
            r8 = 2132019791(0x7f140a4f, float:1.9677927E38)
            java.lang.String r7 = r7.getString(r8)
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r1, r7)
        L88:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK.a(androidx.fragment.app.I, com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration):void");
    }

    @Keep
    public void addEventListener(@NonNull I i, @NonNull OTEventListener oTEventListener) {
        if (!com.google.mlkit.common.internal.model.a.n(i, "OTPublishersHeadlessSDK")) {
            OTLogger.c("OneTrust", 5, "addEventListener: activity passed - null");
            return;
        }
        addEventListener(oTEventListener);
        a eventListenerSetter = this.g;
        ArrayList arrayList = new ArrayList();
        arrayList.add(OTFragmentTags.OT_BANNER_FRAGMENT_TAG);
        arrayList.add(OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG);
        arrayList.add(OTFragmentTags.OT_PREFERENCE_CENTER_DETAILS_FRAGMENT_TAG);
        arrayList.add(OTFragmentTags.OT_VENDOR_LIST_FRAGMENT_TAG);
        arrayList.add(OTFragmentTags.OT_VENDOR_DETAILS_FRAGMENT_TAG);
        arrayList.add(OTFragmentTags.OT_VENDOR_LIST_FILTER_FRAGMENT_TAG);
        arrayList.add(OTFragmentTags.OT_SDK_LIST_FRAGMENT_TAG);
        arrayList.add(OTFragmentTags.OT_SDK_LIST_FILTER_FRAGMENT_TAG);
        arrayList.add(OTFragmentTags.OT_TV_MAIN_FRAGMENT_TAG);
        for (int i2 = 0; i2 < arrayList.size(); i2++) {
            String str = (String) arrayList.get(i2);
            Fragment fragmentE = com.onetrust.otpublishers.headless.Internal.a.g(i, str) ? i.getSupportFragmentManager().E(str) : null;
            if (fragmentE instanceof C4063g) {
                C4063g c4063g = (C4063g) fragmentE;
                c4063g.getClass();
                Intrinsics.checkNotNullParameter(eventListenerSetter, "eventListenerSetter");
                c4063g.t = eventListenerSetter;
            }
            if (fragmentE instanceof l) {
                ((l) fragmentE).c1 = eventListenerSetter;
            }
            if (fragmentE instanceof com.onetrust.otpublishers.headless.UI.fragment.k) {
                ((com.onetrust.otpublishers.headless.UI.fragment.k) fragmentE).x1 = eventListenerSetter;
            }
            if (fragmentE instanceof D) {
                D d = (D) fragmentE;
                d.getClass();
                Intrinsics.checkNotNullParameter(eventListenerSetter, "eventListenerSetter");
                d.s = eventListenerSetter;
            }
        }
    }

    @Keep
    public void appendCustomDataElements(@NonNull JSONObject jSONObject) {
        L.i(jSONObject, new com.onetrust.otpublishers.headless.Internal.Models.a(this.a).b.b().edit(), "OT_DS_DATA_ELEMENT_OBJECT");
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x005a A[Catch: Exception -> 0x0037, TRY_LEAVE, TryCatch #1 {Exception -> 0x0037, blocks: (B:9:0x0025, B:11:0x0031, B:18:0x0054, B:20:0x005a, B:17:0x004f, B:16:0x003a), top: B:30:0x0025, inners: #0 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(@androidx.annotation.NonNull androidx.fragment.app.I r7, com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration r8) {
        /*
            r6 = this;
            java.lang.String r0 = "OneTrust"
            android.content.Context r1 = r6.a
            java.lang.String r2 = "com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER"
            r3 = 0
            android.content.SharedPreferences r2 = r1.getSharedPreferences(r2, r3)
            boolean r4 = com.google.android.gms.internal.mlkit_vision_document_scanner.Q.a(r1)
            java.lang.String r5 = ""
            if (r4 == 0) goto L20
            java.lang.String r3 = "OT_ACTIVE_PROFILE_ID"
            java.lang.String r3 = r2.getString(r3, r5)
            com.onetrust.otpublishers.headless.Internal.Preferences.f r4 = new com.onetrust.otpublishers.headless.Internal.Preferences.f
            r4.<init>(r1, r2, r3)
            r3 = 1
            goto L21
        L20:
            r4 = 0
        L21:
            if (r3 == 0) goto L24
            r2 = r4
        L24:
            r1 = 6
            java.lang.String r3 = "OTT_CULTURE_DOMAIN_DATA"
            java.lang.String r2 = r2.getString(r3, r5)     // Catch: java.lang.Exception -> L37
            boolean r3 = com.onetrust.otpublishers.headless.Internal.a.j(r2)     // Catch: java.lang.Exception -> L37
            if (r3 != 0) goto L4f
            org.json.JSONObject r3 = new org.json.JSONObject     // Catch: java.lang.Exception -> L37 org.json.JSONException -> L39
            r3.<init>(r2)     // Catch: java.lang.Exception -> L37 org.json.JSONException -> L39
            goto L54
        L37:
            r2 = move-exception
            goto L5f
        L39:
            r2 = move-exception
            java.lang.StringBuilder r3 = new java.lang.StringBuilder     // Catch: java.lang.Exception -> L37
            java.lang.String r4 = "error while returning culture domain data, err: "
            r3.<init>(r4)     // Catch: java.lang.Exception -> L37
            java.lang.String r2 = r2.getMessage()     // Catch: java.lang.Exception -> L37
            r3.append(r2)     // Catch: java.lang.Exception -> L37
            java.lang.String r2 = r3.toString()     // Catch: java.lang.Exception -> L37
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r1, r2)     // Catch: java.lang.Exception -> L37
        L4f:
            org.json.JSONObject r3 = new org.json.JSONObject     // Catch: java.lang.Exception -> L37
            r3.<init>()     // Catch: java.lang.Exception -> L37
        L54:
            int r2 = r3.length()     // Catch: java.lang.Exception -> L37
            if (r2 <= 0) goto L65
            java.lang.String r5 = r3.toString()     // Catch: java.lang.Exception -> L37
            goto L65
        L5f:
            java.lang.String r3 = "empty data as SDK not yet initialized "
            r4 = 3
            com.google.android.gms.measurement.internal.Z.n(r3, r2, r0, r4)
        L65:
            boolean r2 = com.onetrust.otpublishers.headless.Internal.a.j(r5)
            if (r2 != 0) goto L7c
            com.onetrust.otpublishers.headless.Internal.Event.a r0 = r6.g
            com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReason r1 = new com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReason
            r2 = 210(0xd2, float:2.94E-43)
            java.lang.String r3 = com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReason.getResponseMessage(r2)
            r1.<init>(r2, r3)
            com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3609e4.a(r7, r0, r8, r1, r6)
            goto L88
        L7c:
            android.content.Context r7 = r6.a
            r8 = 2132019791(0x7f140a4f, float:1.9677927E38)
            java.lang.String r7 = r7.getString(r8)
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r1, r7)
        L88:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK.b(androidx.fragment.app.I, com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:135:0x040d  */
    /* JADX WARN: Removed duplicated region for block: B:151:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:59:0x015a  */
    /* JADX WARN: Type inference failed for: r3v13 */
    /* JADX WARN: Type inference failed for: r3v14 */
    /* JADX WARN: Type inference failed for: r3v5 */
    /* JADX WARN: Type inference failed for: r3v6, types: [int] */
    /* JADX WARN: Type inference failed for: r8v10 */
    /* JADX WARN: Type inference failed for: r8v11, types: [com.google.android.material.snackbar.h] */
    /* JADX WARN: Type inference failed for: r8v15 */
    /* JADX WARN: Type inference failed for: r8v2 */
    /* JADX WARN: Type inference failed for: r8v9 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void callSetupUI(@androidx.annotation.NonNull final androidx.fragment.app.I r27, int r28, final com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration r29) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 1074
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK.callSetupUI(androidx.fragment.app.I, int, com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x005c A[Catch: Exception -> 0x0039, TRY_LEAVE, TryCatch #0 {Exception -> 0x0039, blocks: (B:9:0x0027, B:11:0x0033, B:18:0x0056, B:20:0x005c, B:17:0x0051, B:16:0x003c), top: B:51:0x0027, inners: #3 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void callShowConsentPreferencesUI(@androidx.annotation.NonNull androidx.fragment.app.I r8, com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration r9) {
        /*
            Method dump skipped, instructions count: 261
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK.callShowConsentPreferencesUI(androidx.fragment.app.I, com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration):void");
    }

    @Keep
    public void clearOTSDKConfigurationData() {
        new d(this.a, "OT_SDK_APP_CONFIGURATION").a();
    }

    @Keep
    public void clearOTSDKData() {
        com.onetrust.otpublishers.headless.Internal.a.p(this.a);
        reInitiateLocalVariable();
    }

    @Keep
    public void deleteProfile(String str, @NonNull OTCallback oTCallback) {
        if (str == null || com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            OTLogger.c("OneTrust", 5, "Empty profileId passed to delete the profile.");
            oTCallback.onFailure(new OTResponse(OTResponseType.OT_ERROR, 13, this.a.getResources().getString(R.string.ott_profile_delete_profile_error), ""));
        } else {
            new c(this.a).g(oTCallback, this, str, this.e, this.f, this.a.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0).getBoolean("OT_MULTI_PROFILE_DOWNLOAD_DATA_AFTER_SWITCH", false));
            reInitiateLocalVariable();
        }
    }

    @Keep
    public void dismissUI(@NonNull I i) {
        if (!isOTUIPresent(i)) {
            OTLogger.c("OTPublishersHeadlessSDK", 5, "No OneTrust UI is present.");
            return;
        }
        try {
            if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_BANNER_FRAGMENT_TAG)) {
                Fragment fragmentE = i.getSupportFragmentManager().E(OTFragmentTags.OT_BANNER_FRAGMENT_TAG);
                if (fragmentE instanceof C4063g) {
                    ((C4063g) fragmentE).G();
                }
            }
            if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG)) {
                Fragment fragmentE2 = i.getSupportFragmentManager().E(OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG);
                if (fragmentE2 instanceof l) {
                    ((l) fragmentE2).G();
                }
            }
            if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_PREFERENCE_CENTER_DETAILS_FRAGMENT_TAG)) {
                Fragment fragmentE3 = i.getSupportFragmentManager().E(OTFragmentTags.OT_PREFERENCE_CENTER_DETAILS_FRAGMENT_TAG);
                if (fragmentE3 instanceof com.onetrust.otpublishers.headless.UI.fragment.k) {
                    ((com.onetrust.otpublishers.headless.UI.fragment.k) fragmentE3).G();
                }
            }
            if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_VENDOR_LIST_FRAGMENT_TAG)) {
                Fragment fragmentE4 = i.getSupportFragmentManager().E(OTFragmentTags.OT_VENDOR_LIST_FRAGMENT_TAG);
                if (fragmentE4 instanceof D) {
                    ((D) fragmentE4).G();
                }
            }
            if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_VENDOR_DETAILS_FRAGMENT_TAG)) {
                Fragment fragmentE5 = i.getSupportFragmentManager().E(OTFragmentTags.OT_VENDOR_DETAILS_FRAGMENT_TAG);
                if (fragmentE5 instanceof com.onetrust.otpublishers.headless.UI.fragment.I) {
                    ((com.onetrust.otpublishers.headless.UI.fragment.I) fragmentE5).G();
                }
            }
            if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_SDK_LIST_FRAGMENT_TAG)) {
                Fragment fragmentE6 = i.getSupportFragmentManager().E(OTFragmentTags.OT_SDK_LIST_FRAGMENT_TAG);
                if (fragmentE6 instanceof com.onetrust.otpublishers.headless.UI.fragment.s) {
                    ((com.onetrust.otpublishers.headless.UI.fragment.s) fragmentE6).G();
                }
            }
            if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_VENDOR_LIST_FILTER_FRAGMENT_TAG)) {
                Fragment fragmentE7 = i.getSupportFragmentManager().E(OTFragmentTags.OT_VENDOR_LIST_FILTER_FRAGMENT_TAG);
                if (fragmentE7 instanceof m) {
                    ((m) fragmentE7).G();
                }
            }
            if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_SDK_LIST_FILTER_FRAGMENT_TAG)) {
                Fragment fragmentE8 = i.getSupportFragmentManager().E(OTFragmentTags.OT_SDK_LIST_FILTER_FRAGMENT_TAG);
                if (fragmentE8 instanceof t) {
                    ((t) fragmentE8).G();
                }
            }
            if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_TV_MAIN_FRAGMENT_TAG)) {
                Fragment fragmentE9 = i.getSupportFragmentManager().E(OTFragmentTags.OT_TV_MAIN_FRAGMENT_TAG);
                if (fragmentE9 instanceof g) {
                    ((g) fragmentE9).G();
                }
            }
            if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_IAB_ILLUSTRATION_DETAILS_TAG)) {
                Fragment fragmentE10 = i.getSupportFragmentManager().E(OTFragmentTags.OT_IAB_ILLUSTRATION_DETAILS_TAG);
                if (fragmentE10 instanceof ViewOnClickListenerC4065i) {
                    ((ViewOnClickListenerC4065i) fragmentE10).G();
                }
            }
        } catch (Exception e) {
            Z.n("Something went wrong while closing UI: ", e, "UIUtils", 6);
        }
    }

    @Keep
    public int getAgeGatePromptValue() {
        f fVar;
        Context context = this.a;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        int i = sharedPreferences.getInt("OT_AGE_GATE_USER_CONSENT_STATUS", -1);
        OTLogger.c("AgeGateConsentHandler", 3, "Default Age Gate Consent status :" + i);
        return i;
    }

    @Keep
    public JSONObject getBannerData() {
        f fVar;
        Context context = this.a;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        new d(context);
        new d(context);
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OTT_BANNER_DATA", null);
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return null;
        }
        return new JSONObject(string);
    }

    @NonNull
    @Keep
    public JSONObject getCommonData() {
        f fVar;
        Context context = this.a;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OTT_CULTURE_COMMON_DATA", "");
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                return new JSONObject(string);
            } catch (JSONException e) {
                Z.p("error while returning common data, err: ", e, "OneTrust", 6);
            }
        }
        return new JSONObject();
    }

    @Keep
    public int getConsentStatusForGroupId(@NonNull String str) {
        return new e(this.a).a(str);
    }

    @Keep
    public int getConsentStatusForSDKId(@NonNull String str) {
        return this.b.g.b(str, false);
    }

    @Keep
    public String getCurrentActiveProfile() {
        return this.a.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0).getString("OT_ACTIVE_PROFILE_ID", "");
    }

    @NonNull
    @Keep
    public JSONObject getDomainGroupData() {
        f fVar;
        Context context = this.a;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OTT_CULTURE_DOMAIN_DATA", "");
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                return new JSONObject(string);
            } catch (JSONException e) {
                Z.p("error while returning culture domain data, err: ", e, "OneTrust", 6);
            }
        }
        return new JSONObject();
    }

    @NonNull
    @Keep
    public JSONObject getDomainInfo() {
        f fVar;
        Context context = this.a;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OTT_DOMAIN_DATA", "");
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                return new JSONObject(string);
            } catch (JSONException e) {
                Z.p("error while returning domain data, err: ", e, "OneTrust", 6);
            }
        }
        return new JSONObject();
    }

    @Keep
    public OTGeolocationModel getLastDataDownloadedLocation() {
        f fVar;
        Context context = this.a;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OT_DATA_DOWNLOADED_GEO_LOCATION", "");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return null;
        }
        OTGeolocationModel oTGeolocationModel = new OTGeolocationModel();
        try {
            JSONObject jSONObject = new JSONObject(string);
            oTGeolocationModel.country = jSONObject.optString(AdRevenueScheme.COUNTRY);
            oTGeolocationModel.state = jSONObject.optString("state");
        } catch (JSONException e) {
            Z.p("error in formatting ott data with err = ", e, "GLDataHandler", 6);
        }
        return oTGeolocationModel;
    }

    @Keep
    public OTGeolocationModel getLastUserConsentedLocation() {
        f fVar;
        Context context = this.a;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OT_CONSENTED_LOCATION", "");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return null;
        }
        OTGeolocationModel oTGeolocationModel = new OTGeolocationModel();
        try {
            JSONObject jSONObject = new JSONObject(string);
            oTGeolocationModel.country = jSONObject.optString(AdRevenueScheme.COUNTRY);
            oTGeolocationModel.state = jSONObject.optString("state");
        } catch (JSONException e) {
            Z.p("error in formatting ott data with err = ", e, "GLDataHandler", 6);
        }
        return oTGeolocationModel;
    }

    @NonNull
    @Keep
    public OTCache getOTCache() {
        f fVar;
        Context context = this.a;
        OTCache.OTCacheBuilder oTCacheBuilderNewInstance = OTCache.OTCacheBuilder.newInstance();
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OTT_DATA_SUBJECT_IDENTIFIER", "");
        oTCacheBuilderNewInstance.setDataSubjectIdentifier(string != null ? string : "");
        return oTCacheBuilderNewInstance.build();
    }

    @Keep
    public String getOTConsentJSForWebView() {
        f fVar;
        boolean z;
        Context context = this.a;
        n nVar = new n(context);
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
            z = false;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        if (!"0".equals(sharedPreferences.getString("OTT_LAST_GIVEN_CONSENT", "0"))) {
            return nVar.b(true);
        }
        OTLogger.c("WebviewConsentHelper", 3, "WebviewConsent : user is not interacted, returning default ccpa, groups values. ");
        return nVar.b(false);
    }

    /* JADX WARN: Removed duplicated region for block: B:51:0x0107  */
    @androidx.annotation.Keep
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.onetrust.otpublishers.headless.gcm.consent.OTGoogleConsentModeData getOTGoogleConsentModeData() throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 443
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK.getOTGoogleConsentModeData():com.onetrust.otpublishers.headless.gcm.consent.OTGoogleConsentModeData");
    }

    @NonNull
    @Keep
    public OTVendorUtils getOtVendorUtils() {
        return this.c;
    }

    @Keep
    public JSONObject getPreferenceCenterData() {
        f fVar;
        Context context = this.a;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OTT_PC_DATA", null);
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return null;
        }
        return new JSONObject(string);
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x005b A[Catch: Exception -> 0x0037, TRY_LEAVE, TryCatch #1 {Exception -> 0x0037, blocks: (B:9:0x0025, B:11:0x0031, B:18:0x0055, B:20:0x005b, B:17:0x0050, B:16:0x003a), top: B:35:0x0025, inners: #0 }] */
    @androidx.annotation.Keep
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int getPurposeConsentLocal(@androidx.annotation.NonNull java.lang.String r7) {
        /*
            r6 = this;
            java.lang.String r0 = "OneTrust"
            android.content.Context r1 = r6.a
            java.lang.String r2 = "com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER"
            r3 = 0
            android.content.SharedPreferences r2 = r1.getSharedPreferences(r2, r3)
            boolean r4 = com.google.android.gms.internal.mlkit_vision_document_scanner.Q.a(r1)
            java.lang.String r5 = ""
            if (r4 == 0) goto L20
            java.lang.String r3 = "OT_ACTIVE_PROFILE_ID"
            java.lang.String r3 = r2.getString(r3, r5)
            com.onetrust.otpublishers.headless.Internal.Preferences.f r4 = new com.onetrust.otpublishers.headless.Internal.Preferences.f
            r4.<init>(r1, r2, r3)
            r3 = 1
            goto L21
        L20:
            r4 = 0
        L21:
            if (r3 == 0) goto L24
            r2 = r4
        L24:
            r1 = 3
            java.lang.String r3 = "OTT_CULTURE_DOMAIN_DATA"
            java.lang.String r2 = r2.getString(r3, r5)     // Catch: java.lang.Exception -> L37
            boolean r3 = com.onetrust.otpublishers.headless.Internal.a.j(r2)     // Catch: java.lang.Exception -> L37
            if (r3 != 0) goto L50
            org.json.JSONObject r3 = new org.json.JSONObject     // Catch: java.lang.Exception -> L37 org.json.JSONException -> L39
            r3.<init>(r2)     // Catch: java.lang.Exception -> L37 org.json.JSONException -> L39
            goto L55
        L37:
            r2 = move-exception
            goto L60
        L39:
            r2 = move-exception
            java.lang.StringBuilder r3 = new java.lang.StringBuilder     // Catch: java.lang.Exception -> L37
            java.lang.String r4 = "error while returning culture domain data, err: "
            r3.<init>(r4)     // Catch: java.lang.Exception -> L37
            java.lang.String r2 = r2.getMessage()     // Catch: java.lang.Exception -> L37
            r3.append(r2)     // Catch: java.lang.Exception -> L37
            java.lang.String r2 = r3.toString()     // Catch: java.lang.Exception -> L37
            r3 = 6
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r3, r2)     // Catch: java.lang.Exception -> L37
        L50:
            org.json.JSONObject r3 = new org.json.JSONObject     // Catch: java.lang.Exception -> L37
            r3.<init>()     // Catch: java.lang.Exception -> L37
        L55:
            int r2 = r3.length()     // Catch: java.lang.Exception -> L37
            if (r2 <= 0) goto L65
            java.lang.String r5 = r3.toString()     // Catch: java.lang.Exception -> L37
            goto L65
        L60:
            java.lang.String r3 = "empty data as SDK not yet initialized "
            com.google.android.gms.measurement.internal.Z.n(r3, r2, r0, r1)
        L65:
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r5)
            r2 = -1
            r3 = 5
            java.lang.String r4 = "Purpose Consent Update for id "
            java.lang.String r5 = "OTPublishersHeadlessSDK"
            if (r0 == 0) goto L86
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>(r4)
            r0.append(r7)
            java.lang.String r7 = " : -1, SDK not finished processing"
            r0.append(r7)
            java.lang.String r7 = r0.toString()
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r5, r3, r7)
            return r2
        L86:
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r7)
            if (r0 == 0) goto L92
            java.lang.String r7 = "Empty purpose id passed to get Purpose Consent Update"
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r5, r3, r7)
            return r2
        L92:
            java.lang.String r0 = " : "
            java.lang.StringBuilder r0 = android.support.v4.media.session.a.y(r4, r7, r0)
            com.onetrust.otpublishers.headless.Internal.Helper.s r2 = r6.b
            int r2 = r2.a(r7)
            r0.append(r2)
            java.lang.String r0 = r0.toString()
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r5, r1, r0)
            com.onetrust.otpublishers.headless.Internal.Helper.s r0 = r6.b
            int r7 = r0.a(r7)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK.getPurposeConsentLocal(java.lang.String):int");
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x005b A[Catch: Exception -> 0x0037, TRY_LEAVE, TryCatch #1 {Exception -> 0x0037, blocks: (B:9:0x0025, B:11:0x0031, B:18:0x0055, B:20:0x005b, B:17:0x0050, B:16:0x003a), top: B:41:0x0025, inners: #0 }] */
    @androidx.annotation.Keep
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int getPurposeLegitInterestLocal(@androidx.annotation.NonNull java.lang.String r7) {
        /*
            r6 = this;
            java.lang.String r0 = "OneTrust"
            android.content.Context r1 = r6.a
            java.lang.String r2 = "com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER"
            r3 = 0
            android.content.SharedPreferences r2 = r1.getSharedPreferences(r2, r3)
            boolean r4 = com.google.android.gms.internal.mlkit_vision_document_scanner.Q.a(r1)
            java.lang.String r5 = ""
            if (r4 == 0) goto L20
            java.lang.String r3 = "OT_ACTIVE_PROFILE_ID"
            java.lang.String r3 = r2.getString(r3, r5)
            com.onetrust.otpublishers.headless.Internal.Preferences.f r4 = new com.onetrust.otpublishers.headless.Internal.Preferences.f
            r4.<init>(r1, r2, r3)
            r3 = 1
            goto L21
        L20:
            r4 = 0
        L21:
            if (r3 == 0) goto L24
            r2 = r4
        L24:
            r1 = 3
            java.lang.String r3 = "OTT_CULTURE_DOMAIN_DATA"
            java.lang.String r2 = r2.getString(r3, r5)     // Catch: java.lang.Exception -> L37
            boolean r3 = com.onetrust.otpublishers.headless.Internal.a.j(r2)     // Catch: java.lang.Exception -> L37
            if (r3 != 0) goto L50
            org.json.JSONObject r3 = new org.json.JSONObject     // Catch: java.lang.Exception -> L37 org.json.JSONException -> L39
            r3.<init>(r2)     // Catch: java.lang.Exception -> L37 org.json.JSONException -> L39
            goto L55
        L37:
            r2 = move-exception
            goto L60
        L39:
            r2 = move-exception
            java.lang.StringBuilder r3 = new java.lang.StringBuilder     // Catch: java.lang.Exception -> L37
            java.lang.String r4 = "error while returning culture domain data, err: "
            r3.<init>(r4)     // Catch: java.lang.Exception -> L37
            java.lang.String r2 = r2.getMessage()     // Catch: java.lang.Exception -> L37
            r3.append(r2)     // Catch: java.lang.Exception -> L37
            java.lang.String r2 = r3.toString()     // Catch: java.lang.Exception -> L37
            r3 = 6
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r3, r2)     // Catch: java.lang.Exception -> L37
        L50:
            org.json.JSONObject r3 = new org.json.JSONObject     // Catch: java.lang.Exception -> L37
            r3.<init>()     // Catch: java.lang.Exception -> L37
        L55:
            int r2 = r3.length()     // Catch: java.lang.Exception -> L37
            if (r2 <= 0) goto L65
            java.lang.String r5 = r3.toString()     // Catch: java.lang.Exception -> L37
            goto L65
        L60:
            java.lang.String r3 = "empty data as SDK not yet initialized "
            com.google.android.gms.measurement.internal.Z.n(r3, r2, r0, r1)
        L65:
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r5)
            java.lang.String r2 = "Purpose Legitimate Interest Update for id "
            r3 = -1
            r4 = 5
            java.lang.String r5 = "OTPublishersHeadlessSDK"
            if (r0 == 0) goto L86
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>(r2)
            r0.append(r7)
            java.lang.String r7 = " : -1, SDK not finished processing"
            r0.append(r7)
            java.lang.String r7 = r0.toString()
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r5, r4, r7)
            return r3
        L86:
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r7)
            if (r0 == 0) goto L92
            java.lang.String r7 = "Empty purpose id passed to get Purpose LegitInterest update."
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r5, r4, r7)
            return r3
        L92:
            java.lang.String r0 = "IABV2"
            boolean r0 = r7.startsWith(r0)
            if (r0 != 0) goto Lb7
            java.lang.String r0 = "IAB2V2"
            boolean r0 = r7.startsWith(r0)
            if (r0 != 0) goto Lb7
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>(r2)
            r0.append(r7)
            java.lang.String r7 = " : -1, Invalid purposeId"
            r0.append(r7)
            java.lang.String r7 = r0.toString()
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r5, r4, r7)
            return r3
        Lb7:
            java.lang.String r0 = "Purpose Legit Interest Update for id "
            java.lang.String r2 = " : "
            java.lang.StringBuilder r0 = android.support.v4.media.session.a.y(r0, r7, r2)
            com.onetrust.otpublishers.headless.Internal.Helper.s r2 = r6.b
            int r2 = r2.j(r7)
            r0.append(r2)
            java.lang.String r0 = r0.toString()
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r5, r1, r0)
            com.onetrust.otpublishers.headless.Internal.Helper.s r0 = r6.b
            int r7 = r0.j(r7)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK.getPurposeLegitInterestLocal(java.lang.String):int");
    }

    @Keep
    public int getUCPurposeConsent(@NonNull String str) {
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return this.d.u(str);
        }
        OTLogger.c("OTPublishersHeadlessSDK", 5, "Invalid id passed to get Purposes Consent Status");
        return -1;
    }

    public k getUcpHandler() {
        return this.d;
    }

    @Keep
    public int getVendorCount(@NonNull String str) throws NumberFormatException {
        f fVar;
        boolean z;
        JSONObject jSONObject;
        Context context = this.a;
        int i = 0;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
            z = false;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OT_VENDOR_COUNT_FOR_CATEGORIES", "");
        OTLogger.c("IAB2V2Flow", 3, "Getting vendorCountForCategoryString = " + string);
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            jSONObject = new JSONObject();
        } else {
            try {
                jSONObject = new JSONObject(string);
            } catch (JSONException e) {
                Z.p("Error on getting vendor count for categories : ", e, "OTSPUtils", 6);
            }
        }
        if (jSONObject.length() == 0) {
            OTLogger.c("OneTrust", 6, "getVendorCount: Vendor count data not found");
            return -1;
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j(str) || !jSONObject.has(str)) {
            OTLogger.c("OneTrust", 6, "getVendorCount: Invalid group id passed ");
            return -1;
        }
        String strO = b.o(str, jSONObject);
        if (!com.onetrust.otpublishers.headless.Internal.a.j(strO) && jSONObject.has(str)) {
            i = Integer.parseInt(strO);
        }
        OTLogger.c("OneTrust", 4, "getVendorCount: Vendor count for group " + str + " - " + i);
        return i;
    }

    @Keep
    @Deprecated
    public JSONObject getVendorDetails(@NonNull String str, int i) {
        if (OTVendorListMode.GOOGLE.equalsIgnoreCase(str)) {
            return getVendorDetails(str, String.valueOf(i));
        }
        if (OTVendorListMode.IAB.equalsIgnoreCase(str)) {
            return getVendorDetails(i);
        }
        return null;
    }

    @Keep
    @Deprecated
    public final JSONObject getVendorListData() {
        f fVar;
        Context context = this.a;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OT_IAB_ACTIVE_VENDORLIST", "");
        OTLogger.c("IABHelper", 3, !com.onetrust.otpublishers.headless.Internal.a.j(string) ? AbstractC0147y.d("Saved IAB Active Vendor List : ", string) : "Vendor List is empty");
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                return new JSONObject(string);
            } catch (JSONException e) {
                Z.p("Error on Json object creation, error msg = ", e, "OTPublishersHeadlessSDK", 6);
            }
        }
        return null;
    }

    @Keep
    public JSONObject getVendorListUI(@NonNull String str) {
        if (!OTVendorListMode.GOOGLE.equalsIgnoreCase(str)) {
            return OTVendorListMode.IAB.equalsIgnoreCase(str) ? getVendorListUI() : this.c.getVendorListWithUserSelection(OTVendorListMode.GENERAL);
        }
        JSONObject vendorListWithUserSelection = this.c.getVendorListWithUserSelection(str);
        if (vendorListWithUserSelection.length() > 0) {
            return vendorListWithUserSelection;
        }
        JSONObject vendorListData = getVendorListData(str);
        return vendorListData == null ? new JSONObject() : vendorListData;
    }

    @Keep
    public int isBannerShown(@NonNull Context context) {
        f fVar;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        int i = sharedPreferences.getInt("OneTrustBannerShownToUser", -1);
        OTLogger.c("OneTrust", 4, "Banner shown status : " + i);
        return i;
    }

    @Keep
    public boolean isOTUIPresent(@NonNull I i) {
        return com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_BANNER_FRAGMENT_TAG) || com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG) || com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_TV_MAIN_FRAGMENT_TAG);
    }

    public void loadData(@NonNull String str, @NonNull String str2, @NonNull String str3, @NonNull OTCallback oTCallback, boolean z) {
        f fVar;
        boolean z2;
        if (z) {
            OTLogger.c("OTPublishersHeadlessSDK", 4, "Starting OT SDK network call.");
            if (!com.onetrust.otpublishers.headless.Internal.a.n(str3)) {
                OTLogger.c("OTPublishersHeadlessSDK", 5, this.a.getResources().getString(R.string.warn_invalid_lang));
            }
            new com.onetrust.otpublishers.headless.Internal.Network.d(this.a).c(oTCallback, this, str, str2, str3, this.e, this.f);
            return;
        }
        Context context = this.a;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z2 = true;
        } else {
            fVar = null;
            z2 = false;
        }
        if (z2) {
            sharedPreferences = fVar;
        }
        if (sharedPreferences.getBoolean("OTT_OFFLINE_DATA_SET_FLAG", false)) {
            OTLogger.c("OTPublishersHeadlessSDK", 4, "Load offline data flag set false. Network not reachable. Offline data set. Loading offline data.");
            if (new c(this.a).h(this, oTCallback)) {
                reInitiateLocalVariable();
                return;
            }
            return;
        }
        OTLogger.c("OTPublishersHeadlessSDK", 6, "Server not reachable");
        oTCallback.onFailure(new OTResponse(OTResponseType.OT_ERROR, 6, this.a.getResources().getString(R.string.err_ott_callback_failure) + " as server was not reachable", ""));
    }

    @Keep
    public void optIntoSaleOfData() {
        V.a(new com.onetrust.otpublishers.headless.Internal.Helper.e(this.a).a, "INTERACTION_TYPE", OTConsentInteractionType.PC_CONFIRM);
        if (new p(this.a).b(true, true)) {
            new o(this.a).b(OTConsentInteractionType.PC_CONFIRM);
        }
    }

    @Keep
    public void optOutOfSaleOfData() {
        V.a(new com.onetrust.otpublishers.headless.Internal.Helper.e(this.a).a, "INTERACTION_TYPE", OTConsentInteractionType.PC_CONFIRM);
        if (new p(this.a).b(false, true)) {
            new o(this.a).b(OTConsentInteractionType.PC_CONFIRM);
        }
    }

    @Keep
    @Deprecated
    public boolean overrideDataSubjectIdentifier(@NonNull String str) {
        if (str == null) {
            OTLogger.c("OTPublishersHeadlessSDK", 4, "overrideDataSubjectIdentifier: Pass a valid identifier!!");
            return false;
        }
        c cVar = new c(this.a);
        if (cVar.t()) {
            OTLogger.c("OTPublishersHeadlessSDK", 5, "This method is now deprecated and replaced with renameProfile().");
            return com.onetrust.otpublishers.headless.Internal.a.j(str) ? switchUserProfile(str) : cVar.e(OTRenameProfileParams.OTRenameProfileParamsBuilder.newInstance().setOldProfileID("").setNewProfileID(str).build());
        }
        int i = 2;
        if (!str.isEmpty()) {
            try {
                r rVar = new r(this.a);
                rVar.a(this.a, str);
                rVar.b.c(2);
                return true;
            } catch (JSONException e) {
                Z.p("error in updating consent : ", e, "OTPublishersHeadlessSDK", 6);
                return false;
            }
        }
        Context context = this.a;
        r rVar2 = new r(context);
        if (str.isEmpty()) {
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0);
            String string = sharedPreferences.getString("OT_GENERIC_PROFILE_IDENTIFIER", null);
            if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                string = UUID.randomUUID().toString();
                V.a(sharedPreferences, "OT_GENERIC_PROFILE_IDENTIFIER", string);
            }
            str = string;
            K.c("Generated identifier = ", 4, str, "OTUtils");
            i = 1;
        }
        e eVar = rVar2.b;
        eVar.c(i);
        eVar.k(str);
        rVar2.c();
        return true;
    }

    public void reInitVendorArray() {
        this.c = new OTVendorUtils(getVendorListData(OTVendorListMode.IAB), getVendorListData(OTVendorListMode.GOOGLE), getVendorListData(OTVendorListMode.GENERAL));
    }

    public void reInitiateLocalVariable() {
        this.b = new s(this.a);
        this.d = new k(this.a);
        reInitVendorArray();
    }

    @Keep
    public void refreshUI(@NonNull AbstractActivityC0055k abstractActivityC0055k) {
        if (com.onetrust.otpublishers.headless.Internal.a.g(abstractActivityC0055k, OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG)) {
            try {
                l lVar = (l) abstractActivityC0055k.getSupportFragmentManager().E(OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG);
                if (lVar != null) {
                    lVar.a();
                } else {
                    OTLogger.c("UIUtils", 4, "OTPcFragment not attached to the activity, refreshUI call failed.");
                }
                com.onetrust.otpublishers.headless.UI.fragment.k kVar = (com.onetrust.otpublishers.headless.UI.fragment.k) abstractActivityC0055k.getSupportFragmentManager().E(OTFragmentTags.OT_PREFERENCE_CENTER_DETAILS_FRAGMENT_TAG);
                if (kVar != null) {
                    kVar.a();
                } else {
                    OTLogger.c("UIUtils", 4, "OTPCDetailsFragment not attached to the activity, refreshUI call failed.");
                }
            } catch (Exception e) {
                OTLogger.c("UIUtils", 6, "Exception on refreshing the OT UI. Error: " + e.getMessage());
            }
        }
    }

    @Keep
    public void renameProfile(@NonNull OTRenameProfileParams oTRenameProfileParams, @NonNull OTCallback oTCallback) {
        if (new c(this.a).e(oTRenameProfileParams)) {
            oTCallback.onSuccess(new OTResponse(OTResponseType.OT_SUCCESS, 16, this.a.getResources().getString(R.string.ott_profile_rename_profile_success), ""));
        } else {
            oTCallback.onFailure(new OTResponse(OTResponseType.OT_ERROR, 15, this.a.getResources().getString(R.string.ott_profile_rename_profile_error), ""));
        }
    }

    @Keep
    public void resetUpdatedConsent() {
        OTLogger.c("OTPublishersHeadlessSDK", 4, "Clearing user selections/local variables.");
        reInitiateLocalVariable();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:105:0x01db  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x01fe  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x028f  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0293 A[Catch: JSONException -> 0x02b4, TryCatch #4 {JSONException -> 0x02b4, blocks: (B:120:0x0280, B:123:0x0293, B:124:0x029a, B:126:0x02a0, B:135:0x02c5, B:138:0x02cf), top: B:196:0x0280 }] */
    /* JADX WARN: Removed duplicated region for block: B:4:0x0030  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x014f  */
    /* JADX WARN: Unreachable blocks removed: 2, instructions: 3 */
    @androidx.annotation.Keep
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void saveConsent(@androidx.annotation.NonNull java.lang.String r27) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 1246
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK.saveConsent(java.lang.String):void");
    }

    @Keep
    public void setEnvironment(@NonNull String str) {
        this.e = str;
    }

    @Keep
    public void setFetchDataURL(@NonNull String str) {
        this.f = str;
    }

    public boolean setMultiProfileConfig(OTSdkParams oTSdkParams, @NonNull OTCallback oTCallback, @NonNull c cVar) {
        String strA = cVar.a(oTSdkParams);
        if (!cVar.r(strA)) {
            cVar.s(cVar.a(oTSdkParams));
            OTLogger.c("MultiprofileConsent", 3, "Downloading the data for dsid = " + cVar.m());
            return true;
        }
        d dVar = new com.onetrust.otpublishers.headless.Internal.profile.d(this.a).a;
        if (!dVar.b().getBoolean("OT_MULTI_PROFILE_CONSENT_ENABLED", false)) {
            String strM = cVar.m();
            OTLogger.c("MultiprofileConsent", 4, "Multi Profile Consent is disabled.");
            if (cVar.s(cVar.a(oTSdkParams)) <= 0 || strM == null || com.onetrust.otpublishers.headless.Internal.a.j(strM)) {
                return true;
            }
            dVar.b().edit().putString("OT_MULTI_PROFILE_DELETE_ID", strM).apply();
            return true;
        }
        int iQ = cVar.q();
        int i = dVar.b().getInt("OT_MULTI_PROFILE_MAXIMUM_PROFILES_LIMIT", 6);
        if (iQ < i) {
            OTLogger.c("MultiprofileConsent", 3, "setMultiProfileConfig: profile created and set to " + strA);
            cVar.s(cVar.a(oTSdkParams));
            return true;
        }
        OTLogger.c("MultiprofileConsent", 5, "Max number of profiles already created. Please delete one of the profiles to be able to add a new one.");
        OTLogger.c("MultiprofileConsent", 3, "multiProfileCount = " + iQ + ", multiProfileLimit = " + i);
        oTCallback.onFailure(new OTResponse(OTResponseType.OT_ERROR, 8, this.a.getResources().getString(R.string.err_ott_multi_profile_max_limit), ""));
        return false;
    }

    @Keep
    public boolean setOTCache(@NonNull OTCache oTCache) {
        Context context = this.a;
        if (!Z.r(Boolean.FALSE, context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0), "OT_ENABLE_MULTI_PROFILE")) {
            return com.onetrust.otpublishers.headless.Internal.a.k(context, oTCache.getDataSubjectIdentifier());
        }
        String dataSubjectIdentifier = oTCache.getDataSubjectIdentifier();
        if (dataSubjectIdentifier == null) {
            OTLogger.c("OTCacheHandler", 4, "setDataSubjectIdentifier: Pass a valid identifier.");
            return false;
        }
        OTLogger.c("OTCacheHandler", 5, "This method is now deprecated and replaced with renameProfile().");
        if (com.onetrust.otpublishers.headless.Internal.a.j(dataSubjectIdentifier)) {
            return switchUserProfile(dataSubjectIdentifier);
        }
        return new c(context).e(OTRenameProfileParams.OTRenameProfileParamsBuilder.newInstance().setOldProfileID("").setNewProfileID(dataSubjectIdentifier).build());
    }

    @Keep
    public void setOTOfflineData(@NonNull JSONObject jSONObject) {
        try {
            AbstractC3589c0.a(this.a, this, jSONObject);
            new e(this.a).a.b().edit().putBoolean("OTT_OFFLINE_DATA_SET_FLAG", true).apply();
        } catch (JSONException unused) {
            OTLogger.c("OTPublishersHeadlessSDK", 6, "Error on setting offline data.");
            OTLogger.c("OTPublishersHeadlessSDK", 3, "Setting OfflineDataSetFlag to false.");
            new e(this.a).a.b().edit().putBoolean("OTT_OFFLINE_DATA_SET_FLAG", false).apply();
        }
    }

    @Keep
    public boolean setOTUXParams(@NonNull OTUXParams oTUXParams) {
        boolean z;
        Context context = this.a;
        if (oTUXParams.getUxParam() != null) {
            JSONObject uxParam = oTUXParams.getUxParam();
            SharedPreferences.Editor editorEdit = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0).edit();
            editorEdit.putString("OTT_UX_PARAMS_JSON", uxParam.toString());
            editorEdit.apply();
            z = true;
        } else {
            z = false;
        }
        if (oTUXParams.getOTSDKTheme() != null) {
            String oTSDKTheme = oTUXParams.getOTSDKTheme();
            SharedPreferences.Editor editorEdit2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0).edit();
            editorEdit2.putString("OT_UX_SDK_THEME", oTSDKTheme);
            editorEdit2.apply();
        }
        return z;
    }

    @Keep
    public void setupUI(@NonNull AbstractActivityC0055k abstractActivityC0055k, int i) throws JSONException {
        callSetupUI(abstractActivityC0055k, i, null);
    }

    @Keep
    public boolean shouldShowBanner() {
        return showBannerReason() > -1;
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x0062 A[Catch: Exception -> 0x003f, TRY_LEAVE, TryCatch #1 {Exception -> 0x003f, blocks: (B:13:0x002d, B:15:0x0039, B:22:0x005c, B:24:0x0062, B:21:0x0057, B:20:0x0042), top: B:36:0x002d, outer: #2, inners: #0 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int showBannerReason() {
        /*
            r8 = this;
            java.lang.String r0 = "OneTrust"
            r1 = 6
            r2 = -1
            android.content.Context r3 = r8.a     // Catch: org.json.JSONException -> L27
            java.lang.String r4 = "com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER"
            r5 = 0
            android.content.SharedPreferences r4 = r3.getSharedPreferences(r4, r5)     // Catch: org.json.JSONException -> L27
            com.onetrust.otpublishers.headless.Internal.profile.c r6 = new com.onetrust.otpublishers.headless.Internal.profile.c     // Catch: org.json.JSONException -> L27
            r6.<init>(r3)     // Catch: org.json.JSONException -> L27
            boolean r6 = r6.t()     // Catch: org.json.JSONException -> L27
            java.lang.String r7 = ""
            if (r6 == 0) goto L29
            java.lang.String r5 = "OT_ACTIVE_PROFILE_ID"
            java.lang.String r5 = r4.getString(r5, r7)     // Catch: org.json.JSONException -> L27
            com.onetrust.otpublishers.headless.Internal.Preferences.f r6 = new com.onetrust.otpublishers.headless.Internal.Preferences.f     // Catch: org.json.JSONException -> L27
            r6.<init>(r3, r4, r5)     // Catch: org.json.JSONException -> L27
            r5 = 1
            goto L2a
        L27:
            r0 = move-exception
            goto L94
        L29:
            r6 = 0
        L2a:
            if (r5 == 0) goto L2d
            r4 = r6
        L2d:
            java.lang.String r3 = "OTT_CULTURE_DOMAIN_DATA"
            java.lang.String r3 = r4.getString(r3, r7)     // Catch: java.lang.Exception -> L3f
            boolean r4 = com.onetrust.otpublishers.headless.Internal.a.j(r3)     // Catch: java.lang.Exception -> L3f
            if (r4 != 0) goto L57
            org.json.JSONObject r4 = new org.json.JSONObject     // Catch: java.lang.Exception -> L3f org.json.JSONException -> L41
            r4.<init>(r3)     // Catch: java.lang.Exception -> L3f org.json.JSONException -> L41
            goto L5c
        L3f:
            r3 = move-exception
            goto L67
        L41:
            r3 = move-exception
            java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch: java.lang.Exception -> L3f
            java.lang.String r5 = "error while returning culture domain data, err: "
            r4.<init>(r5)     // Catch: java.lang.Exception -> L3f
            java.lang.String r3 = r3.getMessage()     // Catch: java.lang.Exception -> L3f
            r4.append(r3)     // Catch: java.lang.Exception -> L3f
            java.lang.String r3 = r4.toString()     // Catch: java.lang.Exception -> L3f
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r1, r3)     // Catch: java.lang.Exception -> L3f
        L57:
            org.json.JSONObject r4 = new org.json.JSONObject     // Catch: java.lang.Exception -> L3f
            r4.<init>()     // Catch: java.lang.Exception -> L3f
        L5c:
            int r3 = r4.length()     // Catch: java.lang.Exception -> L3f
            if (r3 <= 0) goto L7d
            java.lang.String r7 = r4.toString()     // Catch: java.lang.Exception -> L3f
            goto L7d
        L67:
            java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch: org.json.JSONException -> L27
            java.lang.String r5 = "empty data as SDK not yet initialized "
            r4.<init>(r5)     // Catch: org.json.JSONException -> L27
            java.lang.String r3 = r3.getMessage()     // Catch: org.json.JSONException -> L27
            r4.append(r3)     // Catch: org.json.JSONException -> L27
            java.lang.String r3 = r4.toString()     // Catch: org.json.JSONException -> L27
            r4 = 3
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r4, r3)     // Catch: org.json.JSONException -> L27
        L7d:
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r7)     // Catch: org.json.JSONException -> L27
            if (r0 == 0) goto L84
            return r2
        L84:
            com.onetrust.otpublishers.headless.Internal.Models.b r0 = new com.onetrust.otpublishers.headless.Internal.Models.b     // Catch: org.json.JSONException -> L27
            android.content.Context r3 = r8.a     // Catch: org.json.JSONException -> L27
            r0.<init>(r3)     // Catch: org.json.JSONException -> L27
            org.json.JSONObject r3 = r8.getBannerData()     // Catch: org.json.JSONException -> L27
            int r2 = r0.b(r3)     // Catch: org.json.JSONException -> L27
            goto L9b
        L94:
            java.lang.String r3 = "Error while computing show banner status,returning default value as false: "
            java.lang.String r4 = "OTPublishersHeadlessSDK"
            com.google.android.gms.measurement.internal.Z.p(r3, r0, r4, r1)
        L9b:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK.showBannerReason():int");
    }

    @Keep
    public void showBannerUI(@NonNull AbstractActivityC0055k abstractActivityC0055k) {
        a(abstractActivityC0055k, null);
    }

    @Keep
    public void showConsentPurposesUI(@NonNull I i) {
        callShowConsentPreferencesUI(i, null);
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x005c A[Catch: Exception -> 0x0039, TRY_LEAVE, TryCatch #1 {Exception -> 0x0039, blocks: (B:9:0x0027, B:11:0x0033, B:18:0x0056, B:20:0x005c, B:17:0x0051, B:16:0x003c), top: B:49:0x0027, inners: #2 }] */
    @androidx.annotation.Keep
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void showConsentUI(@androidx.annotation.NonNull androidx.fragment.app.I r9, int r10, com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration r11, @androidx.annotation.NonNull com.onetrust.otpublishers.headless.Public.OTConsentUICallback r12) {
        /*
            Method dump skipped, instructions count: 239
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK.showConsentUI(androidx.fragment.app.I, int, com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration, com.onetrust.otpublishers.headless.Public.OTConsentUICallback):void");
    }

    @Keep
    public void showPreferenceCenterUI(@NonNull AbstractActivityC0055k abstractActivityC0055k) {
        b(abstractActivityC0055k, null);
    }

    @Keep
    public void startSDK(@NonNull String str, @NonNull String str2, @NonNull String str3, OTSdkParams oTSdkParams, @NonNull OTCallback oTCallback) {
        a(str, str2, str3, oTSdkParams, false, oTCallback);
    }

    @Keep
    @Deprecated
    public boolean switchUserProfile(@NonNull String str) {
        boolean zL = new c(this.a).l(null, this, str, this.e, this.f, false);
        if (zL) {
            reInitiateLocalVariable();
        }
        return zL;
    }

    public void updateAllSDKConsentStatus(@NonNull JSONArray jSONArray, boolean z) throws JSONException {
        com.onetrust.otpublishers.headless.Internal.Helper.g gVar = this.b.g;
        String string = gVar.a.getString("OT_INTERNAL_SDK_STATUS_MAP", "");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return;
        }
        try {
            JSONObject jSONObject = new JSONObject(string);
            int i = 0;
            while (true) {
                int length = jSONArray.length();
                JSONObject jSONObject2 = gVar.c;
                if (i >= length) {
                    OTLogger.c("SdkListHelper", 4, "Updated All SDK status for  - " + jSONObject2);
                    return;
                }
                String string2 = jSONArray.get(i).toString();
                if (jSONObject.has(string2) && 2 != jSONObject.getInt(string2)) {
                    jSONObject2.put(string2, z ? 1 : 0);
                }
                i++;
            }
        } catch (JSONException e) {
            Z.p("Error while updating all sdk status ", e, "SdkListHelper", 6);
        }
    }

    @Keep
    public void updateAllVendorsConsentLocal(@NonNull String str, boolean z) {
        this.c.updateAllVendorsConsentLocal(str, z);
        this.c.updateVendorObjectLocalState(str);
    }

    @Keep
    public void updatePurposeConsent(@NonNull String str, boolean z) {
        f fVar;
        boolean z2;
        if (this.b.n(str, z)) {
            try {
                s sVar = this.b;
                OTVendorUtils oTVendorUtils = this.c;
                Context context = sVar.a;
                SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (AbstractC3605e0.a(new d(context, "OTT_DEFAULT_USER").b().getString("OT_ENABLE_MULTI_PROFILE", Boolean.FALSE.toString()))) {
                    fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                    z2 = true;
                } else {
                    fVar = null;
                    z2 = false;
                }
                if ((z2 ? fVar : sharedPreferences).getBoolean("OT_GENERAL_VENDORS_CONFIGURED", false)) {
                    if (z2) {
                        sharedPreferences = fVar;
                    }
                    if (sharedPreferences.getBoolean("OT_GENERAL_VENDORS_TOGGLE_CONFIGURED", false)) {
                        if (com.onetrust.otpublishers.headless.Internal.a.j(sVar.f)) {
                            try {
                                sVar.f = sVar.k();
                            } catch (JSONException unused) {
                                OTLogger.c("CustomGroupDetails", 6, "Error on creating valid consent able parent child map.");
                            }
                        }
                        oTVendorUtils.updateVendorConsentStatusBasedOnCategoryStatus(OTVendorListMode.GENERAL, str, sVar.f, z, this);
                        return;
                    }
                }
                OTLogger.c("GeneralVendors", 5, "Cannot update consent for the Vendor ID:General Vendor data with opt-out not found in template settings");
            } catch (JSONException unused2) {
                OTLogger.c("OTPublishersHeadlessSDK", 6, "Error on updating general vendor status.");
            }
        }
    }

    @Keep
    public void updatePurposeLegitInterest(@NonNull String str, boolean z) throws JSONException {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            OTLogger.c("OTPublishersHeadlessSDK", 5, "Empty purpose id passed to update Purpose LegitInterest method.");
            return;
        }
        if (!str.startsWith("IABV2") && !str.startsWith("IAB2V2")) {
            OTLogger.c("OTPublishersHeadlessSDK", 5, "Invalid ID " + str + " passed to update Purpose LegitInterest");
            return;
        }
        s sVar = this.b;
        try {
            if (!new JSONObject(sVar.d.getString("OTT_IAB_CONSENTABLE_PURPOSES", "")).getJSONObject("purposeLegitimateInterests").has(com.onetrust.otpublishers.headless.Internal.Helper.c.q(str))) {
                OTLogger.c("CustomGroupDetails", 5, "Legitimate Interest value not updated for Purpose ".concat(str));
                return;
            }
            sVar.c.put(str, z ? 1 : 0);
            OTLogger.c("CustomGroupDetails", 4, "Legitimate Interest value updated for Purpose " + str + " with value : " + z);
        } catch (Exception e) {
            Z.n("error in updating purpose legitimate interest status. err = ", e, "CustomGroupDetails", 6);
        }
    }

    public void updateSDKConsentStatus(@NonNull String str, boolean z) {
        this.b.g.h(str, z);
    }

    @Keep
    public void updateUCPurposeConsent(@NonNull String str, @NonNull String str2, @NonNull String str3, boolean z) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str3) || com.onetrust.otpublishers.headless.Internal.a.j(str2) || com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            OTLogger.c("OTPublishersHeadlessSDK", 5, "Invalid id passed to update Custom Preference Options");
            return;
        }
        if (getUCPurposeConsent(str3) < 1) {
            OTLogger.c("OTPublishersHeadlessSDK", 5, "Purpose consent for " + str3 + " is disabled, thus Custom Preference cannot be enabled");
            return;
        }
        this.d.g(str2, str.trim() + str3.trim() + str2.trim(), str, z);
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x005e, code lost:
    
        if (r1.getBoolean("OT_GENERAL_VENDORS_TOGGLE_CONFIGURED", false) != false) goto L33;
     */
    @androidx.annotation.Keep
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void updateVendorConsent(@androidx.annotation.NonNull java.lang.String r9, @androidx.annotation.NonNull java.lang.String r10, boolean r11) {
        /*
            r8 = this;
            java.lang.String r0 = "google"
            boolean r0 = r0.equalsIgnoreCase(r9)
            java.lang.String r1 = "Empty vendor id passed to updateVendorConsent method."
            r2 = 5
            if (r0 != 0) goto L67
            java.lang.String r0 = "iab"
            boolean r0 = r0.equalsIgnoreCase(r9)
            if (r0 == 0) goto L14
            goto L67
        L14:
            java.lang.String r0 = "general"
            boolean r0 = r0.equalsIgnoreCase(r9)
            if (r0 == 0) goto L66
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r10)
            java.lang.String r3 = "GeneralVendors"
            if (r0 == 0) goto L28
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r3, r2, r1)
            return
        L28:
            android.content.Context r0 = r8.a
            java.lang.String r1 = "com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER"
            r4 = 0
            android.content.SharedPreferences r1 = r0.getSharedPreferences(r1, r4)
            boolean r5 = com.google.android.gms.internal.mlkit_vision_document_scanner.Q.a(r0)
            if (r5 == 0) goto L46
            java.lang.String r5 = "OT_ACTIVE_PROFILE_ID"
            java.lang.String r6 = ""
            java.lang.String r5 = r1.getString(r5, r6)
            com.onetrust.otpublishers.headless.Internal.Preferences.f r6 = new com.onetrust.otpublishers.headless.Internal.Preferences.f
            r6.<init>(r0, r1, r5)
            r0 = 1
            goto L48
        L46:
            r6 = 0
            r0 = r4
        L48:
            if (r0 == 0) goto L4c
            r5 = r6
            goto L4d
        L4c:
            r5 = r1
        L4d:
            java.lang.String r7 = "OT_GENERAL_VENDORS_CONFIGURED"
            boolean r5 = r5.getBoolean(r7, r4)
            if (r5 == 0) goto L61
            if (r0 == 0) goto L58
            r1 = r6
        L58:
            java.lang.String r0 = "OT_GENERAL_VENDORS_TOGGLE_CONFIGURED"
            boolean r0 = r1.getBoolean(r0, r4)
            if (r0 == 0) goto L61
            goto L73
        L61:
            java.lang.String r9 = "Cannot update consent for the Vendor ID:General Vendor data with opt-out not found in template settings"
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r3, r2, r9)
        L66:
            return
        L67:
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r10)
            if (r0 == 0) goto L73
            java.lang.String r9 = "OTPublishersHeadlessSDK"
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r9, r2, r1)
            return
        L73:
            com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils r0 = r8.c
            r0.updateVendorConsentStatus(r9, r10, r11)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK.updateVendorConsent(java.lang.String, java.lang.String, boolean):void");
    }

    @Keep
    public void updateVendorLegitInterest(@NonNull String str, @NonNull String str2, boolean z) {
        if (OTVendorListMode.GOOGLE.equalsIgnoreCase(str)) {
            OTLogger.c("OTPublishersHeadlessSDK", 5, "Legitimate Interest not supported for Google vendors.");
        } else {
            updateVendorLegitInterest(str2, z);
        }
    }

    @Keep
    public void writeLogsToFile(boolean z, boolean z2) throws IOException {
        if (z) {
            OTLogger.open(this.a.getFilesDir() + "/OTPublisherHeadlessSDKLogs.log", 2, 1000000);
        } else if (z2 && !z) {
            OTLogger.c("OTPublishersHeadlessSDK", 4, "Write To File Should be Enabled!");
        }
        OTLogger.g = z;
        OTLogger.h = z2;
    }

    @Keep
    public int getConsentStatusForGroupId(@NonNull String str, @NonNull String str2) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            K.c("Invalid custom group Id passed - ", 4, str, "OTPublishersHeadlessSDK");
            return -1;
        }
        int iA = new e(this.a).a(str);
        return iA == -1 ? "active".equalsIgnoreCase(str2) ? 1 : 0 : iA;
    }

    @Keep
    @Deprecated
    public JSONObject getVendorDetails(int i) {
        try {
            JSONObject vendorListWithUserSelectionWithoutFallback = this.c.getVendorListWithUserSelectionWithoutFallback(OTVendorListMode.IAB);
            if (vendorListWithUserSelectionWithoutFallback == null) {
                vendorListWithUserSelectionWithoutFallback = getVendorListData(OTVendorListMode.IAB);
            }
            if (vendorListWithUserSelectionWithoutFallback == null) {
                vendorListWithUserSelectionWithoutFallback = new JSONObject();
            }
            return X.a(this.a, i, OTVendorUtils.getVendorsListObject(vendorListWithUserSelectionWithoutFallback, String.valueOf(i)));
        } catch (JSONException e) {
            Z.p(VENDOR_DETAILS_ERROR_MSG, e, "OTPublishersHeadlessSDK", 6);
            return null;
        }
    }

    @Keep
    @Deprecated
    public JSONObject getVendorListUI() {
        JSONObject vendorListWithUserSelection = this.c.getVendorListWithUserSelection(OTVendorListMode.IAB);
        if ((vendorListWithUserSelection == null || vendorListWithUserSelection.length() <= 0) && (vendorListWithUserSelection = getVendorListData(OTVendorListMode.IAB)) == null) {
            vendorListWithUserSelection = new JSONObject();
        }
        OTLogger.c("OTPublishersHeadlessSDK", 3, "getVendorListUI: " + vendorListWithUserSelection.length() + "," + vendorListWithUserSelection);
        return vendorListWithUserSelection;
    }

    @Keep
    @Deprecated
    public void renameProfile(@NonNull String str, @NonNull String str2, @NonNull OTCallback oTCallback) {
        renameProfile(OTRenameProfileParams.OTRenameProfileParamsBuilder.newInstance().setOldProfileID(str).setNewProfileID(str2).build(), oTCallback);
    }

    @Keep
    public void setupUI(@NonNull I i, int i2) throws JSONException {
        callSetupUI(i, i2, null);
    }

    @Keep
    public void showBannerUI(@NonNull I i) {
        a(i, null);
    }

    @Keep
    public void showPreferenceCenterUI(@NonNull I i) {
        b(i, null);
    }

    @Keep
    public void startSDK(@NonNull String str, @NonNull String str2, @NonNull String str3, OTSdkParams oTSdkParams, boolean z, @NonNull OTCallback oTCallback) {
        a(str, str2, str3, oTSdkParams, z, oTCallback);
    }

    @Keep
    public void switchUserProfile(@NonNull String str, @NonNull OTCallback oTCallback) {
        if (new c(this.a).l(oTCallback, this, str, this.e, this.f, this.a.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0).getBoolean("OT_MULTI_PROFILE_DOWNLOAD_DATA_AFTER_SWITCH", false))) {
            reInitiateLocalVariable();
        }
    }

    @Keep
    public void updateAllVendorsConsentLocal(boolean z) {
        this.c.updateAllVendorsConsentLocal(OTVendorListMode.IAB, z);
    }

    @Keep
    public int getUCPurposeConsent(@NonNull String str, @NonNull String str2) {
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str2) && !com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return this.d.a(str, str2);
        }
        OTLogger.c("OTPublishersHeadlessSDK", 5, "Invalid id passed to get UCP Topic Consent Status");
        return -1;
    }

    @Keep
    public void setupUI(@NonNull I i, int i2, @NonNull OTConfiguration oTConfiguration) throws JSONException {
        callSetupUI(i, i2, oTConfiguration);
    }

    public void showBannerUI(@NonNull I i, @NonNull OTConfiguration oTConfiguration) {
        a(i, oTConfiguration);
    }

    @Keep
    public void showPreferenceCenterUI(@NonNull I i, @NonNull OTConfiguration oTConfiguration) {
        b(i, oTConfiguration);
    }

    @Keep
    @Deprecated
    public void updateVendorLegitInterest(@NonNull String str, boolean z) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            OTLogger.c("OTPublishersHeadlessSDK", 5, "Empty vendor id passed to updateVendorLegitInterest method.");
            return;
        }
        try {
            if (getDomainGroupData().isNull("LegIntSettings")) {
                return;
            }
            if (getDomainGroupData().getJSONObject("LegIntSettings").getBoolean("PAllowLI")) {
                this.c.updateVendorLegitInterest(OTVendorListMode.IAB, str, z);
                return;
            }
            OTLogger.c("OTPublishersHeadlessSDK", 5, "Not updated LI value for vendor ID " + str + ", LI not configured for this vendor Id.");
        } catch (Exception e) {
            Z.n("Error while checking LI feature toggle", e, "OTPublishersHeadlessSDK", 6);
        }
    }

    @Keep
    public int getUCPurposeConsent(@NonNull String str, @NonNull String str2, @NonNull String str3) {
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str3) && !com.onetrust.otpublishers.headless.Internal.a.j(str2) && !com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return this.d.b(str, str3, str2);
        }
        OTLogger.c("OTPublishersHeadlessSDK", 5, "Invalid id passed to get UCP Custom Preference Option Consent Status");
        return -1;
    }

    @Keep
    public void updateUCPurposeConsent(@NonNull String str, @NonNull String str2, boolean z) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str2) || com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            OTLogger.c("OTPublishersHeadlessSDK", 5, "Invalid id passed to update Topics");
            return;
        }
        if (getUCPurposeConsent(str2) < 1) {
            OTLogger.c("OTPublishersHeadlessSDK", 5, "Purpose consent for " + str2 + " is disabled, thus topic cannot be enabled");
            return;
        }
        this.d.t(str.trim() + str2.trim(), str, z);
    }

    @Keep
    @Deprecated
    public boolean deleteProfile(String str) {
        if (str == null || com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            OTLogger.c("OneTrust", 5, "Empty profileId passed to delete the profile.");
            return false;
        }
        boolean zG = new c(this.a).g(null, this, str, this.e, this.f, false);
        reInitiateLocalVariable();
        return zG;
    }

    @Keep
    public JSONObject getVendorDetails(@NonNull String str, @NonNull String str2) {
        try {
            if (OTVendorListMode.IAB.equalsIgnoreCase(str)) {
                JSONObject vendorDetails = getVendorDetails(Integer.parseInt(str2));
                OTLogger.c("OTPublishersHeadlessSDK", 3, "Vendor mode = " + str + ", Vendor details for ID:" + str2 + " " + vendorDetails);
                return vendorDetails;
            }
            if (OTVendorListMode.GOOGLE.equalsIgnoreCase(str)) {
                JSONObject vendorListWithUserSelectionWithoutFallback = this.c.getVendorListWithUserSelectionWithoutFallback(str);
                if (vendorListWithUserSelectionWithoutFallback == null) {
                    vendorListWithUserSelectionWithoutFallback = getVendorListData(str);
                }
                if (vendorListWithUserSelectionWithoutFallback == null) {
                    vendorListWithUserSelectionWithoutFallback = new JSONObject();
                }
                JSONObject vendorsListObject = OTVendorUtils.getVendorsListObject(vendorListWithUserSelectionWithoutFallback, str2);
                OTLogger.c("OTPublishersHeadlessSDK", 3, "Vendor mode = " + str + ", Vendor details for ID:" + str2 + " " + vendorsListObject);
                return vendorsListObject;
            }
            JSONObject vendorListWithUserSelectionWithoutFallback2 = this.c.getVendorListWithUserSelectionWithoutFallback(str);
            if (vendorListWithUserSelectionWithoutFallback2 == null) {
                vendorListWithUserSelectionWithoutFallback2 = getVendorListData(str);
            }
            if (vendorListWithUserSelectionWithoutFallback2 == null) {
                vendorListWithUserSelectionWithoutFallback2 = new JSONObject();
            }
            JSONObject vendorsListObject2 = OTVendorUtils.getVendorsListObject(vendorListWithUserSelectionWithoutFallback2, str2);
            OTLogger.c("OTPublishersHeadlessSDK", 3, "Vendor mode = " + str + ", Vendor details for ID:" + str2 + " " + vendorsListObject2);
            return vendorsListObject2;
        } catch (JSONException e) {
            Z.p(VENDOR_DETAILS_ERROR_MSG, e, "OTPublishersHeadlessSDK", 6);
            return null;
        }
    }

    @Keep
    public void updateUCPurposeConsent(@NonNull String str, boolean z) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            OTLogger.c("OTPublishersHeadlessSDK", 5, "Invalid id passed to update Purposes");
        } else {
            this.d.j(str, z);
        }
    }

    @Keep
    public void refreshUI(@NonNull I i) {
        if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG)) {
            try {
                l lVar = (l) i.getSupportFragmentManager().E(OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG);
                if (lVar != null) {
                    lVar.a();
                } else {
                    OTLogger.c("UIUtils", 4, "OTPcFragment not attached to the activity, refreshUI call failed.");
                }
                com.onetrust.otpublishers.headless.UI.fragment.k kVar = (com.onetrust.otpublishers.headless.UI.fragment.k) i.getSupportFragmentManager().E(OTFragmentTags.OT_PREFERENCE_CENTER_DETAILS_FRAGMENT_TAG);
                if (kVar != null) {
                    kVar.a();
                } else {
                    OTLogger.c("UIUtils", 4, "OTPCDetailsFragment not attached to the activity, refreshUI call failed.");
                }
            } catch (Exception e) {
                OTLogger.c("UIUtils", 6, "Exception on refreshing the OT UI. Error: " + e.getMessage());
            }
        }
    }

    @Keep
    @Deprecated
    public void updateVendorConsent(@NonNull String str, boolean z) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            OTLogger.c("OTPublishersHeadlessSDK", 5, "Empty vendor id passed to updateVendorConsent method.");
        } else {
            this.c.updateVendorConsentStatus(OTVendorListMode.IAB, str, z);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:47:0x0102 A[PHI: r11
  0x0102: PHI (r11v2 java.lang.String) = 
  (r11v1 java.lang.String)
  (r11v1 java.lang.String)
  (r11v1 java.lang.String)
  (r11v1 java.lang.String)
  (r11v1 java.lang.String)
  (r11v1 java.lang.String)
  (r11v1 java.lang.String)
  (r11v1 java.lang.String)
  (r11v1 java.lang.String)
  (r11v32 java.lang.String)
 binds: [B:8:0x005d, B:10:0x0067, B:12:0x006d, B:14:0x0077, B:16:0x0081, B:18:0x008b, B:48:0x0104, B:50:0x010a, B:52:0x0110, B:46:0x0100] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(@androidx.annotation.NonNull java.lang.String r31, @androidx.annotation.NonNull java.lang.String r32, @androidx.annotation.NonNull java.lang.String r33, com.onetrust.otpublishers.headless.Public.DataModel.OTSdkParams r34, boolean r35, @androidx.annotation.NonNull com.onetrust.otpublishers.headless.Public.OTCallback r36) {
        /*
            Method dump skipped, instructions count: 1323
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK.a(java.lang.String, java.lang.String, java.lang.String, com.onetrust.otpublishers.headless.Public.DataModel.OTSdkParams, boolean, com.onetrust.otpublishers.headless.Public.OTCallback):void");
    }

    @Keep
    public void addEventListener(@NonNull OTEventListener oTEventListener) {
        a aVar = this.g;
        aVar.getClass();
        OTLogger.c("EventListenerSetter", 3, "clear OTEventListener.");
        aVar.a.clear();
        a aVar2 = this.g;
        aVar2.getClass();
        if (oTEventListener == null) {
            OTLogger.c("EventListenerSetter", 3, "OtEventListener set with null called.");
            return;
        }
        OTLogger.c("EventListenerSetter", 3, "Add OtEventListener, value = " + oTEventListener);
        aVar2.a.add(oTEventListener);
    }

    @Keep
    public void updatePurposeConsent(@NonNull String str, boolean z, boolean z2) throws JSONException {
        boolean z3;
        boolean z4;
        f fVar;
        if (z2) {
            s sVar = this.b;
            OTVendorUtils oTVendorUtils = this.c;
            if (sVar.n(str, z)) {
                if (com.onetrust.otpublishers.headless.Internal.a.j(sVar.f)) {
                    try {
                        sVar.f = sVar.k();
                    } catch (JSONException unused) {
                        OTLogger.c("CustomGroupDetails", 6, "Error on creating valid consent able parent child map.");
                    }
                }
                String str2 = sVar.f;
                if (!com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
                    try {
                        JSONObject jSONObject = new JSONObject(str2);
                        if (jSONObject.has(str)) {
                            JSONArray jSONArray = jSONObject.getJSONArray(str);
                            for (int i = 0; i < jSONArray.length(); i++) {
                                String string = jSONArray.get(i).toString();
                                sVar.n(string, z);
                                sVar.e(string, z);
                            }
                        } else {
                            JSONObject jSONObject2 = new JSONObject(sVar.e.a.b().getString("DOMAIN_PARENT_ID_MAP", ""));
                            String string2 = jSONObject2.has(str) ? jSONObject2.getString(str) : null;
                            if (string2 != null && !com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                                JSONArray jSONArray2 = jSONObject.getJSONArray(string2);
                                int i2 = 0;
                                while (true) {
                                    if (i2 >= jSONArray2.length()) {
                                        z3 = true;
                                        break;
                                    } else {
                                        if (sVar.a(jSONArray2.get(i2).toString()) != 1) {
                                            z3 = false;
                                            break;
                                        }
                                        i2++;
                                    }
                                }
                                sVar.n(string2, z3);
                            }
                        }
                    } catch (JSONException e) {
                        Z.p("Error on getting parent child JSON. Error message = ", e, "CustomGroupDetails", 6);
                    }
                }
                try {
                    Context context = sVar.a;
                    SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                    if (AbstractC3605e0.a(new d(context, "OTT_DEFAULT_USER").b().getString("OT_ENABLE_MULTI_PROFILE", Boolean.FALSE.toString()))) {
                        fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                        z4 = true;
                    } else {
                        z4 = false;
                        fVar = null;
                    }
                    if ((z4 ? fVar : sharedPreferences).getBoolean("OT_GENERAL_VENDORS_CONFIGURED", false)) {
                        if (z4) {
                            sharedPreferences = fVar;
                        }
                        if (sharedPreferences.getBoolean("OT_GENERAL_VENDORS_TOGGLE_CONFIGURED", false)) {
                            if (com.onetrust.otpublishers.headless.Internal.a.j(sVar.f)) {
                                try {
                                    sVar.f = sVar.k();
                                } catch (JSONException unused2) {
                                    OTLogger.c("CustomGroupDetails", 6, "Error on creating valid consent able parent child map.");
                                }
                            }
                            oTVendorUtils.updateVendorConsentStatusBasedOnCategoryStatus(OTVendorListMode.GENERAL, str, sVar.f, z, this);
                            return;
                        }
                    }
                    OTLogger.c("GeneralVendors", 5, "Cannot update consent for the Vendor ID:General Vendor data with opt-out not found in template settings");
                    return;
                } catch (JSONException unused3) {
                    OTLogger.c("CustomGroupDetails", 6, "Error on updating general vendor status.");
                    return;
                }
            }
            return;
        }
        updatePurposeConsent(str, z);
    }

    @Keep
    public JSONObject getVendorListData(@NonNull String str) {
        f fVar;
        JSONObject jSONObject;
        Context context = this.a;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (OTVendorListMode.GENERAL.equalsIgnoreCase(str)) {
            if (z) {
                sharedPreferences = fVar;
            }
            String string = sharedPreferences.getString("OT_GENERAL_VENDORS", "");
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                try {
                    jSONObject = new JSONObject(string);
                } catch (JSONException e) {
                    W.a("Something went wrong while parsing savedGeneral Vendors: ", e, "GeneralVendors", 3);
                }
            } else {
                jSONObject = new JSONObject();
            }
            OTLogger.c("OTPublishersHeadlessSDK", 4, "Saved General Vendors : " + jSONObject);
            return jSONObject;
        }
        if (OTVendorListMode.GOOGLE.equalsIgnoreCase(str)) {
            if (z) {
                sharedPreferences = fVar;
            }
            try {
                String string2 = sharedPreferences.getString("OT_GOOGLE_ACTIVE_VENDOR_LIST", null);
                if (!com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                    return new JSONObject(string2);
                }
            } catch (JSONException e2) {
                Z.p("error while getting culture data json on getActiveGoogleVendors, err: ", e2, "OneTrust", 6);
            }
            return null;
        }
        return getVendorListData();
    }
}
