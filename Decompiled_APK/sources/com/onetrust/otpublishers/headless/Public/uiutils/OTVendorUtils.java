package com.onetrust.otpublishers.headless.Public.uiutils;

import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Helper.c;
import com.onetrust.otpublishers.headless.Internal.Helper.u;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class OTVendorUtils {
    public static final String CONSENT_TYPE = "consent";
    public static final String LEGITIMATE_CONSENT_TYPE = "legIntStatus";
    public ItemListener a;
    public JSONObject b;
    public JSONObject c;
    public JSONObject d;
    public JSONObject e;
    public JSONObject f;
    public JSONObject g;
    public u generalVendorStatus;
    public JSONObject h;
    public JSONObject i;

    public interface ItemListener {
        void onItemClick(@NonNull String str, boolean z);
    }

    public OTVendorUtils(JSONObject jSONObject, JSONObject jSONObject2, JSONObject jSONObject3) {
        this.b = new JSONObject();
        this.d = new JSONObject();
        if (jSONObject != null) {
            this.b = jSONObject;
        }
        if (jSONObject2 != null) {
            this.d = jSONObject2;
        }
        if (jSONObject3 != null) {
            this.f = jSONObject3;
            u uVar = new u();
            new JSONObject();
            uVar.a = jSONObject3;
            this.generalVendorStatus = uVar;
        }
    }

    public static void a(@NonNull String str, @NonNull String str2, boolean z, @NonNull JSONObject jSONObject, @NonNull JSONObject jSONObject2) throws JSONException {
        jSONObject2.putOpt(str, z ? "1" : "0");
        jSONObject.put(str2, jSONObject2);
    }

    public void clearValues(JSONObject jSONObject, JSONObject jSONObject2, JSONObject jSONObject3) {
        if (jSONObject == null) {
            jSONObject = new JSONObject();
        }
        this.b = jSONObject;
        this.c = null;
        if (jSONObject2 == null) {
            jSONObject2 = new JSONObject();
        }
        this.d = jSONObject2;
        this.e = null;
        if (this.f == null) {
            this.f = new JSONObject();
            this.generalVendorStatus.a = new JSONObject();
        } else {
            this.f = jSONObject3;
            this.generalVendorStatus.a = jSONObject3;
        }
        this.generalVendorStatus.b = null;
    }

    @NonNull
    public JSONObject getVendorListWithUserSelection(@NonNull String str) {
        if (OTVendorListMode.GOOGLE.equalsIgnoreCase(str)) {
            JSONObject jSONObject = this.e;
            return jSONObject == null ? this.d : jSONObject;
        }
        if (OTVendorListMode.IAB.equalsIgnoreCase(str)) {
            JSONObject jSONObject2 = this.c;
            return jSONObject2 == null ? this.b : jSONObject2;
        }
        u uVar = this.generalVendorStatus;
        JSONObject jSONObject3 = uVar.b;
        return jSONObject3 == null ? uVar.a : jSONObject3;
    }

    public JSONObject getVendorListWithUserSelectionWithoutFallback(@NonNull String str) {
        return OTVendorListMode.GOOGLE.equalsIgnoreCase(str) ? this.e : OTVendorListMode.IAB.equalsIgnoreCase(str) ? this.c : this.generalVendorStatus.b;
    }

    @NonNull
    public JSONObject getVendorsByPurpose(@NonNull Map<String, String> map, JSONObject jSONObject) {
        String str;
        JSONObject jSONObject2 = new JSONObject();
        if (jSONObject != null) {
            for (Map.Entry<String, String> entry : map.entrySet()) {
                String strQ = c.q(entry.getKey());
                String value = entry.getValue();
                value.getClass();
                switch (value) {
                    case "IAB2V2_FEATURE":
                    case "IAB2_FEATURE":
                        str = "features";
                        break;
                    case "IAB2_PURPOSE":
                    case "IAB2V2_PURPOSE":
                        str = "purposes";
                        break;
                    case "IAB2V2_SPL_FEATURE":
                    case "IAB2_SPL_FEATURE":
                        str = "specialFeatures";
                        break;
                    case "IAB2V2_STACK":
                    case "IAB2_STACK":
                        str = "stacks";
                        break;
                    case "IAB2V2_SPL_PURPOSE":
                    case "IAB2_SPL_PURPOSE":
                        str = "specialPurposes";
                        break;
                    default:
                        str = null;
                        break;
                }
                if (str != null) {
                    try {
                        a(jSONObject, jSONObject2, strQ, str);
                    } catch (Exception e) {
                        Z.n("Vendors purpose list data error ", e, "VendorArray", 6);
                    }
                }
            }
        }
        return jSONObject2;
    }

    @NonNull
    public JSONObject getVendorsListObject(@NonNull String str) {
        return OTVendorListMode.GOOGLE.equalsIgnoreCase(str) ? this.d : OTVendorListMode.IAB.equalsIgnoreCase(str) ? this.b : this.f;
    }

    public boolean isAllVendorEnabled(@NonNull JSONObject jSONObject) throws JSONException {
        String string;
        JSONArray jSONArrayNames = jSONObject.names();
        if (jSONArrayNames != null) {
            for (int i = 0; i < jSONArrayNames.length(); i++) {
                try {
                    string = jSONArrayNames.getString(i);
                } catch (JSONException e) {
                    Z.p("Vendor list data error ", e, "OneTrust", 6);
                }
                if ("0".equalsIgnoreCase(jSONObject.getJSONObject(string).getString(CONSENT_TYPE))) {
                    OTLogger.c("VendorArray", 4, "consent status 0 for vendorID = " + string);
                } else {
                    continue;
                }
            }
            return true;
        }
        return false;
    }

    public void refreshList(@NonNull String str) {
        JSONObject jSONObject;
        JSONObject jSONObject2;
        if (OTVendorListMode.GOOGLE.equalsIgnoreCase(str) && (jSONObject2 = this.e) != null) {
            this.d = jSONObject2;
        } else if (!OTVendorListMode.IAB.equalsIgnoreCase(str) || (jSONObject = this.c) == null) {
            this.f = this.generalVendorStatus.b;
        } else {
            this.b = jSONObject;
        }
    }

    public void saveVendorConsentStatus(@NonNull SharedPreferences sharedPreferences, JSONObject jSONObject, JSONObject jSONObject2) {
        if (jSONObject != null) {
            L.i(jSONObject, sharedPreferences.edit(), "OT_IAB_ACTIVE_VENDORLIST");
        }
        if (jSONObject2 != null) {
            L.i(jSONObject2, sharedPreferences.edit(), "OT_GOOGLE_ACTIVE_VENDOR_LIST");
        }
        u uVar = this.generalVendorStatus;
        OTLogger.c("GeneralVendors", 4, "General Vendors saved as " + uVar.a);
        L.i(uVar.a, sharedPreferences.edit(), "OT_GENERAL_VENDORS");
    }

    public void setFilteredList(@NotNull String str, @NotNull JSONObject jSONObject, boolean z) {
        if (OTVendorListMode.GENERAL.equalsIgnoreCase(str)) {
            this.h = jSONObject;
        } else if (OTVendorListMode.IAB.equalsIgnoreCase(str)) {
            this.g = jSONObject;
        } else if (OTVendorListMode.GOOGLE.equalsIgnoreCase(str)) {
            this.i = jSONObject;
        }
        if (z) {
            updateSelectAllButtonStatus(str);
        }
    }

    public void setSelectAllButtonListener(ItemListener itemListener) {
        this.a = itemListener;
    }

    public void setVendorsListObject(@NonNull String str, @NonNull JSONObject jSONObject, boolean z) {
        if (OTVendorListMode.GOOGLE.equalsIgnoreCase(str)) {
            this.d = jSONObject;
        } else if (OTVendorListMode.IAB.equalsIgnoreCase(str)) {
            this.b = jSONObject;
        } else {
            this.f = jSONObject;
        }
        if (z) {
            updateSelectAllButtonStatus(str);
        }
    }

    public void updateAllGeneralVendorState(boolean z, @NonNull String str, @NonNull JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        JSONArray jSONArrayNames;
        if (jSONObject2 == null || (jSONArrayNames = jSONObject2.names()) == null) {
            return;
        }
        for (int i = 0; i < jSONArrayNames.length(); i++) {
            try {
                String string = jSONArrayNames.getString(i);
                if (jSONObject.has(string)) {
                    JSONObject jSONObject3 = jSONObject.getJSONObject(string);
                    updateGeneralVendorsConsent(z, str, jSONObject3);
                    jSONObject.put(string, jSONObject3);
                }
            } catch (JSONException e) {
                Z.p("error in reading string from JSONObject, error = ", e, "VendorArray", 6);
            }
        }
    }

    public void updateAllVendorState(boolean z, @NonNull String str, @NonNull JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        JSONArray jSONArrayNames;
        if (jSONObject2 == null || (jSONArrayNames = jSONObject2.names()) == null) {
            return;
        }
        for (int i = 0; i < jSONArrayNames.length(); i++) {
            try {
                String string = jSONArrayNames.getString(i);
                if (jSONObject.has(string)) {
                    JSONObject jSONObject3 = jSONObject.getJSONObject(string);
                    updateVendorsConsent(z, str, jSONObject3);
                    jSONObject.put(string, jSONObject3);
                }
            } catch (JSONException e) {
                Z.p("error in reading string from JSONObject, error = ", e, "VendorArray", 6);
            }
        }
    }

    public void updateAllVendorsConsentLocal(@NonNull String str, boolean z) {
        if (OTVendorListMode.GOOGLE.equalsIgnoreCase(str)) {
            updateAllVendorState(z, CONSENT_TYPE, this.d, a(str));
            return;
        }
        boolean zEqualsIgnoreCase = OTVendorListMode.IAB.equalsIgnoreCase(str);
        JSONObject jSONObjectA = a(str);
        if (zEqualsIgnoreCase) {
            updateAllVendorState(z, CONSENT_TYPE, this.b, jSONObjectA);
        } else {
            updateAllGeneralVendorState(z, CONSENT_TYPE, this.generalVendorStatus.a, jSONObjectA);
        }
    }

    public void updateGeneralVendorsConsent(boolean z, @NonNull String str, @NonNull JSONObject jSONObject) throws JSONException {
        if (jSONObject.getInt(str) <= -1 || jSONObject.getInt(str) == 2) {
            return;
        }
        jSONObject.putOpt(str, z ? "1" : "0");
    }

    public void updateSelectAllButtonStatus(@NonNull String str) {
        JSONObject jSONObject = OTVendorListMode.IAB.equalsIgnoreCase(str) ? this.g : OTVendorListMode.GENERAL.equalsIgnoreCase(str) ? this.h : OTVendorListMode.GOOGLE.equalsIgnoreCase(str) ? this.i : null;
        if (OTVendorListMode.GENERAL.equalsIgnoreCase(str)) {
            if (jSONObject == null) {
                jSONObject = this.f;
            }
        } else if (OTVendorListMode.GOOGLE.equalsIgnoreCase(str)) {
            if (jSONObject == null) {
                jSONObject = this.d;
            }
        } else if (jSONObject == null) {
            jSONObject = this.b;
        }
        ItemListener itemListener = this.a;
        if (itemListener != null) {
            itemListener.onItemClick(str, isAllVendorEnabled(jSONObject));
        }
    }

    public void updateVendorConsentStatus(@NonNull String str, @NonNull String str2, boolean z) {
        try {
            if (!a(str, str2, false)) {
                OTLogger.c("VendorArray", 6, "Not updated consent for Vendor (" + str2 + "), Consent not configured for this vendor Id.");
                return;
            }
            OTLogger.c("VendorArray", 4, "Vendor (" + str2 + ") consent updated to " + z + ".");
            a(str, CONSENT_TYPE, str2, z);
        } catch (JSONException e) {
            Z.p("JSON exception on category status map put call. Error msg = ", e, "VendorArray", 6);
        }
    }

    public void updateVendorConsentStatusBasedOnCategoryStatus(@NonNull String str, @NonNull String str2, @NonNull String str3, boolean z, @NonNull OTPublishersHeadlessSDK oTPublishersHeadlessSDK) {
        if (OTVendorListMode.GENERAL.equalsIgnoreCase(str)) {
            HashMap map = new HashMap();
            map.put(str2, "COOKIE");
            JSONObject jSONObject = new JSONObject(str3);
            if (jSONObject.has(str2)) {
                JSONArray jSONArray = jSONObject.getJSONArray(str2);
                for (int i = 0; i < jSONArray.length(); i++) {
                    map.put(jSONArray.get(i).toString(), "COOKIE");
                }
            }
            JSONArray jSONArrayNames = com.google.mlkit.vision.documentscanner.internal.c.b(map, oTPublishersHeadlessSDK.getVendorListUI(OTVendorListMode.GENERAL)).names();
            if (jSONArrayNames != null) {
                for (int i2 = 0; i2 < jSONArrayNames.length(); i2++) {
                    oTPublishersHeadlessSDK.updateVendorConsent(str, jSONArrayNames.getString(i2), z);
                }
            }
        }
    }

    public void updateVendorLegitInterest(@NonNull String str, @NonNull String str2, boolean z) {
        try {
            if (!a(str, str2, true)) {
                OTLogger.c("VendorArray", 6, "Not updated LI for Vendor (" + str2 + "), LI not configured for this vendor Id.");
                return;
            }
            a(str, LEGITIMATE_CONSENT_TYPE, str2, z);
            OTLogger.c("VendorArray", 4, "Vendor (" + str2 + ")  legit interest updated to " + z + ".");
        } catch (JSONException e) {
            Z.p("JSON exception on category status map put call. Error msg = ", e, "VendorArray", 6);
        }
    }

    public void updateVendorObjectLocalState(@NonNull String str) {
        if (OTVendorListMode.GENERAL.equalsIgnoreCase(str)) {
            if (getVendorListWithUserSelectionWithoutFallback(str) == null) {
                u uVar = this.generalVendorStatus;
                new JSONObject();
                uVar.b = uVar.a;
                return;
            }
            return;
        }
        if (OTVendorListMode.GOOGLE.equalsIgnoreCase(str)) {
            if (getVendorListWithUserSelectionWithoutFallback(str) == null) {
                this.e = this.d;
            }
        } else if (OTVendorListMode.IAB.equalsIgnoreCase(str) && getVendorListWithUserSelectionWithoutFallback(str) == null) {
            this.c = this.b;
        }
    }

    public void updateVendorsConsent(boolean z, @NonNull String str, @NonNull JSONObject jSONObject) throws JSONException {
        if (jSONObject.getInt(str) > -1) {
            jSONObject.putOpt(str, z ? "1" : "0");
        }
    }

    @NonNull
    public static JSONObject getVendorsListObject(@NonNull JSONObject jSONObject, @NonNull String str) {
        return jSONObject.has(str) ? jSONObject.getJSONObject(str) : new JSONObject();
    }

    public final JSONObject a(@NonNull String str) {
        JSONObject jSONObject = OTVendorListMode.IAB.equalsIgnoreCase(str) ? this.g : OTVendorListMode.GENERAL.equalsIgnoreCase(str) ? this.h : OTVendorListMode.GOOGLE.equalsIgnoreCase(str) ? this.i : null;
        if (jSONObject == null) {
            if (OTVendorListMode.GOOGLE.equalsIgnoreCase(str)) {
                return this.d;
            }
            if (OTVendorListMode.IAB.equalsIgnoreCase(str)) {
                return this.b;
            }
            if (OTVendorListMode.GENERAL.equalsIgnoreCase(str)) {
                return this.f;
            }
        }
        return jSONObject;
    }

    public final boolean a(@NonNull String str, @NonNull String str2, boolean z) {
        try {
            JSONObject vendorListWithUserSelection = getVendorListWithUserSelection(str);
            if (vendorListWithUserSelection.has(str2) && z) {
                if (vendorListWithUserSelection.getJSONObject(str2).getInt(LEGITIMATE_CONSENT_TYPE) > -1) {
                    return true;
                }
            } else if (vendorListWithUserSelection.has(str2) && !z && vendorListWithUserSelection.getJSONObject(str2).getInt(CONSENT_TYPE) > -1) {
                return true;
            }
            return false;
        } catch (Exception e) {
            Z.n("unable to get vendor status ", e, "VendorArray", 6);
            return false;
        }
    }

    public static void a(@NonNull JSONObject jSONObject, @NonNull JSONObject jSONObject2, @NonNull String str, @NonNull String str2) throws JSONException {
        Iterator<String> itKeys = jSONObject.keys();
        while (itKeys.hasNext()) {
            String next = itKeys.next();
            JSONObject jSONObject3 = jSONObject.getJSONObject(next);
            Objects.requireNonNull(str2);
            int i = 0;
            if (str2.equals("purposes")) {
                JSONArray jSONArray = jSONObject3.getJSONArray("purposes");
                if (jSONObject3.getJSONArray(str2).length() > 0) {
                    for (int i2 = 0; i2 < jSONArray.length(); i2++) {
                        if (jSONArray.getString(i2).equals(str)) {
                            jSONObject2.put(next, jSONObject3);
                        }
                    }
                }
                if (jSONObject3.getJSONArray("legIntPurposes").length() > 0 && jSONObject3.getInt(LEGITIMATE_CONSENT_TYPE) >= 0) {
                    while (i < jSONObject3.getJSONArray("legIntPurposes").length()) {
                        if (jSONObject3.getJSONArray("legIntPurposes").getString(i).equals(str)) {
                            jSONObject2.put(next, jSONObject3);
                        }
                        i++;
                    }
                }
            } else {
                JSONArray jSONArray2 = jSONObject3.getJSONArray(str2);
                if (jSONObject3.getJSONArray(str2).length() > 0) {
                    while (i < jSONArray2.length()) {
                        if (jSONArray2.getString(i).equals(str)) {
                            jSONObject2.put(next, jSONObject3);
                        }
                        i++;
                    }
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x00e9 A[PHI: r0 r10
  0x00e9: PHI (r0v8 org.json.JSONObject) = (r0v7 org.json.JSONObject), (r0v12 org.json.JSONObject) binds: [B:48:0x00e7, B:38:0x00c6] A[DONT_GENERATE, DONT_INLINE]
  0x00e9: PHI (r10v4 org.json.JSONObject) = (r10v2 org.json.JSONObject), (r10v8 org.json.JSONObject) binds: [B:48:0x00e7, B:38:0x00c6] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00ef A[PHI: r0 r10
  0x00ef: PHI (r0v10 org.json.JSONObject) = (r0v7 org.json.JSONObject), (r0v12 org.json.JSONObject) binds: [B:48:0x00e7, B:38:0x00c6] A[DONT_GENERATE, DONT_INLINE]
  0x00ef: PHI (r10v6 org.json.JSONObject) = (r10v2 org.json.JSONObject), (r10v8 org.json.JSONObject) binds: [B:48:0x00e7, B:38:0x00c6] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(@androidx.annotation.NonNull java.lang.String r10, @androidx.annotation.NonNull java.lang.String r11, @androidx.annotation.NonNull java.lang.String r12, boolean r13) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 250
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils.a(java.lang.String, java.lang.String, java.lang.String, boolean):void");
    }
}
