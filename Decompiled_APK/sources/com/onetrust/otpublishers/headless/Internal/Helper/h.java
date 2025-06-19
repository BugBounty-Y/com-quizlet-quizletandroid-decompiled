package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.util.Base64;
import androidx.camera.camera2.internal.a0;
import androidx.camera.camera2.internal.c0;
import com.amazon.device.ads.WebResourceService;
import com.facebook.internal.H;
import com.facebook.internal.J;
import com.google.android.gms.internal.measurement.A3;
import com.google.android.gms.internal.measurement.E3;
import com.google.android.gms.internal.measurement.G3;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.measurement.W2;
import com.google.android.gms.internal.measurement.W3;
import com.google.android.gms.internal.measurement.Y3;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3538u;
import com.google.android.gms.internal.mlkit_vision_common.F2;
import com.google.android.gms.internal.mlkit_vision_common.G2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.Z;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABTCFKeys;
import com.quizlet.data.model.D;
import com.quizlet.db.data.models.persisted.DBGroupFolder;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class h implements androidx.lifecycle.viewmodel.b, com.bumptech.glide.util.pool.a, com.google.android.gms.measurement.internal.r, com.google.gson.internal.n, com.google.firebase.components.d, com.quizlet.local.ormlite.util.c {
    public static h b;
    public static ArrayList c;
    public static boolean d;
    public final /* synthetic */ int a;

    public /* synthetic */ h(int i) {
        this.a = i;
    }

    public static synchronized h a(boolean z) {
        try {
            if (b == null) {
                d = z;
                b = new h(0);
                ArrayList arrayList = new ArrayList(Arrays.asList("IABTCF_CmpSdkID.int", "IABTCF_CmpSdkVersion.int", "IABTCF_PolicyVersion.int", "IABTCF_gdprApplies.int", "IABTCF_PublisherCC.string", "IABTCF_PurposeOneTreatment.int", "IABTCF_TCString.string", "IABTCF_VendorConsents.string", "IABTCF_VendorLegitimateInterests.string", "IABTCF_PurposeConsents.string", "IABTCF_PurposeLegitimateInterests.string", "IABTCF_SpecialFeaturesOptIns.string", "IABTCF_PublisherConsent.string", "IABTCF_PublisherLegitimateInterests.string", "IABTCF_PublisherCustomPurposesConsents.string", "IABTCF_PublisherCustomPurposesLegitimateInterests.string", "IABTCF_PublisherRestrictions1.string", "IABTCF_PublisherRestrictions2.string", "IABTCF_PublisherRestrictions3.string", "IABTCF_PublisherRestrictions4.string", "IABTCF_PublisherRestrictions5.string", "IABTCF_PublisherRestrictions6.string", "IABTCF_PublisherRestrictions7.string", "IABTCF_PublisherRestrictions8.string", "IABTCF_PublisherRestrictions9.string", "IABTCF_PublisherRestrictions10.string", "IABTCF_PublisherRestrictions11.string"));
                c = arrayList;
                arrayList.add(d ? "IABTCF_UseNonStandardTexts.int" : "IABTCF_UseNonStandardStacks.int");
            }
        } catch (Throwable th) {
            throw th;
        }
        return b;
    }

    public static String b(Context context, JSONObject jSONObject) throws Throwable {
        SharedPreferences.Editor editorEdit;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
        SharedPreferences.Editor editor = null;
        try {
            editorEdit = defaultSharedPreferences.edit();
        } catch (Throwable th) {
            th = th;
        }
        try {
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (new com.onetrust.otpublishers.headless.Internal.profile.c(context).t()) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                z = true;
            } else {
                fVar = null;
                z = false;
            }
            new com.onetrust.otpublishers.headless.gpp.b(context);
            if (z) {
                sharedPreferences = fVar;
            }
            boolean z2 = sharedPreferences.getBoolean("OT_GPP_IS_ENABLED", false);
            boolean zContains = defaultSharedPreferences.contains("IABTCF_TCString");
            String str = i(jSONObject, editorEdit, z2, zContains) + "." + p(jSONObject, editorEdit, z2, zContains);
            editorEdit.putString(z2 ? OTGppKeys.IAB_GPP_TCFEU2_STRING : "IABTCF_TCString", str);
            if (z2 && zContains) {
                editorEdit.putString("IABTCF_TCString", str);
            }
            editorEdit.apply();
            return str;
        } catch (Throwable th2) {
            th = th2;
            editor = editorEdit;
            if (editor != null) {
                editor.apply();
            }
            throw th;
        }
    }

    public static String d(Integer num, Integer num2) {
        String binaryString = Integer.toBinaryString(num.intValue());
        StringBuilder sb = new StringBuilder();
        for (int iIntValue = num2.intValue() - binaryString.length(); iIntValue > 0; iIntValue--) {
            sb.append('0');
        }
        sb.append(binaryString);
        return sb.toString();
    }

    public static String e(String str) {
        int length = str.length() % 8;
        if (length > 0) {
            StringBuilder sb = new StringBuilder(str);
            for (int i = 8 - length; i > 0; i--) {
                sb.append('0');
            }
            str = sb.toString();
        }
        int length2 = str.length() / 8;
        byte[] bArr = new byte[length2];
        for (int i2 = 0; i2 < length2; i2++) {
            int i3 = i2 * 8;
            bArr[i2] = Integer.valueOf(Integer.parseInt(str.substring(i3, i3 + 8), 2)).byteValue();
        }
        return new String(Base64.encode(bArr, 2)).replace("+", "-").replace("/", "_").replace(SimpleComparison.EQUAL_TO_OPERATION, "");
    }

    /* JADX WARN: Removed duplicated region for block: B:120:0x0476  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x04fd  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x050d A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:142:0x0335 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:84:0x03d0 A[Catch: Exception -> 0x03e9, JSONException -> 0x03ee, TryCatch #10 {JSONException -> 0x03ee, Exception -> 0x03e9, blocks: (B:82:0x03c5, B:84:0x03d0, B:86:0x03e1, B:91:0x03f3, B:92:0x03fb, B:94:0x0401, B:96:0x0415, B:98:0x041b, B:104:0x0429), top: B:144:0x03c5 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String i(org.json.JSONObject r34, android.content.SharedPreferences.Editor r35, boolean r36, boolean r37) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 1335
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.h.i(org.json.JSONObject, android.content.SharedPreferences$Editor, boolean, boolean):java.lang.String");
    }

    public static JSONObject j(Context context, SharedPreferences sharedPreferences) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        HashMap map = new com.onetrust.otpublishers.headless.gpp.b(context).b;
        if (!map.keySet().isEmpty()) {
            for (String str : map.keySet()) {
                if (!com.onetrust.otpublishers.headless.Internal.a.j(str) && (str.startsWith("IABGPP_TCFEU2_") || str.equals(OTGppKeys.IAB_GPP_TCFEU2_STRING))) {
                    Integer num = (Integer) map.get(str);
                    if (Objects.equals(num, 10)) {
                        jSONObject.put(str, sharedPreferences.getInt(str, -1));
                    } else if (Objects.equals(num, 30)) {
                        jSONObject.put(str, sharedPreferences.getString(str, ""));
                    }
                }
            }
        }
        return jSONObject;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0025 A[PHI: r4
  0x0025: PHI (r4v2 java.lang.String) = (r4v0 java.lang.String), (r4v1 java.lang.String) binds: [B:6:0x0023, B:9:0x0030] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void k(android.content.Context r6) {
        /*
            android.content.SharedPreferences r6 = android.preference.PreferenceManager.getDefaultSharedPreferences(r6)
            android.content.SharedPreferences$Editor r6 = r6.edit()
            java.util.ArrayList r0 = com.onetrust.otpublishers.headless.Internal.Helper.h.c
            java.util.Iterator r0 = r0.iterator()
            java.lang.String r1 = ""
            r2 = r1
        L11:
            boolean r3 = r0.hasNext()
            if (r3 == 0) goto L37
            java.lang.Object r3 = r0.next()
            java.lang.String r3 = (java.lang.String) r3
            java.lang.String r4 = ".int"
            boolean r5 = r3.endsWith(r4)
            if (r5 == 0) goto L2a
        L25:
            java.lang.String r2 = r3.replace(r4, r1)
            goto L33
        L2a:
            java.lang.String r4 = ".string"
            boolean r5 = r3.endsWith(r4)
            if (r5 == 0) goto L33
            goto L25
        L33:
            r6.remove(r2)
            goto L11
        L37:
            java.lang.String r0 = "IABTCF_UseNonStandardStacks"
            r6.remove(r0)
            java.lang.String r0 = "IABTCF_UseNonStandardTexts"
            r6.remove(r0)
            r6.apply()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.h.k(android.content.Context):void");
    }

    public static void l(SharedPreferences.Editor editor) {
        editor.remove("IABTCF_PublisherRestrictions1");
        editor.remove("IABTCF_PublisherRestrictions2");
        editor.remove("IABTCF_PublisherRestrictions3");
        editor.remove("IABTCF_PublisherRestrictions4");
        editor.remove("IABTCF_PublisherRestrictions5");
        editor.remove("IABTCF_PublisherRestrictions6");
        editor.remove("IABTCF_PublisherRestrictions7");
        editor.remove("IABTCF_PublisherRestrictions8");
        editor.remove("IABTCF_PublisherRestrictions9");
        editor.remove("IABTCF_PublisherRestrictions10");
        editor.remove("IABTCF_PublisherRestrictions11");
        editor.apply();
    }

    public static void m(JSONObject jSONObject, SharedPreferences.Editor editor, String str, String str2, String str3, String str4, String str5) throws JSONException {
        int i;
        String str6;
        editor.putInt("IABTCF_gdprApplies", jSONObject.getInt("gdprApplies"));
        editor.putInt("IABTCF_CmpSdkID", jSONObject.getInt("CmpId"));
        editor.putInt(OTIABTCFKeys.IABTCF_CMPSDKVERSION, jSONObject.getInt("CmpVersion"));
        editor.putInt(OTIABTCFKeys.IABTCF_POLICYVERSION, jSONObject.getInt("TcfPolicyVersion"));
        if (d) {
            i = jSONObject.getInt("UseNonStandardStacks");
            str6 = OTIABTCFKeys.IABTCF_USENONSTANDARDTEXTS;
        } else {
            i = jSONObject.getInt("UseNonStandardStacks");
            str6 = OTIABTCFKeys.IABTCF_USENONSTANDARDSTACKS;
        }
        editor.putInt(str6, i);
        editor.putString(OTIABTCFKeys.IABTCF_SPECIALFEATURESOPTINS, str);
        editor.putString("IABTCF_PurposeConsents", str2);
        editor.putString(OTIABTCFKeys.IABTCF_PUBLISHERCONSENT, str2);
        editor.putString(OTIABTCFKeys.IABTCF_PURPOSELEGITIMATEINTERESTS, str3);
        editor.putString(OTIABTCFKeys.IABTCF_PUBLISHERLEGITIMATEINTERESTS, str3);
        editor.putInt("IABTCF_PurposeOneTreatment", jSONObject.getInt("PurposeOneTreatment"));
        editor.putString("IABTCF_PublisherCC", jSONObject.getString("PublisherCC"));
        editor.putString("IABTCF_VendorConsents", str4);
        editor.putString("IABTCF_VendorLegitimateInterests", str5);
    }

    public static String n(String str) {
        String upperCase = str.toUpperCase(Locale.ENGLISH);
        StringBuilder sb = new StringBuilder();
        ArrayList arrayList = new ArrayList(Arrays.asList("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"));
        for (int i = 0; i < upperCase.length(); i++) {
            sb.append(d(Integer.valueOf(arrayList.indexOf(String.valueOf(upperCase.charAt(i)))), 6));
        }
        return sb.toString();
    }

    public static String o(JSONArray jSONArray, Integer num) {
        String str;
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < num.intValue()) {
            i++;
            int i2 = 0;
            while (true) {
                if (i2 >= jSONArray.length()) {
                    str = "0";
                    break;
                }
                try {
                } catch (JSONException e) {
                    Z.p("error while getting Array Integer : ", e, "TCF2Encoder", 6);
                }
                if (jSONArray.getInt(i2) == i) {
                    str = "1";
                    break;
                }
                i2++;
            }
            sb.append(str);
        }
        return sb.toString();
    }

    public static String p(JSONObject jSONObject, SharedPreferences.Editor editor, boolean z, boolean z2) throws JSONException {
        String str;
        String str2;
        JSONArray jSONArray = new JSONArray();
        jSONArray.put(d(3, 3));
        jSONArray.put(o(jSONObject.getJSONArray("PurposesConsent"), 24));
        jSONArray.put(o(jSONObject.getJSONArray("PurposesLITransparency"), 24));
        int i = jSONObject.getInt("NumCustomPurposes");
        jSONArray.put(d(Integer.valueOf(i), 6));
        if (z) {
            str2 = OTGppKeys.IAB_GPP_PUBLISHERCUSTOMPURPOSESCONSENTS;
            str = OTGppKeys.IAB_GPP_PUBLISHERCUSTOMPURPOSESLEGITIMATEINTERESTS;
        } else {
            str = OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESLEGITIMATEINTERESTS;
            str2 = OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESCONSENTS;
        }
        if (i > 0) {
            jSONArray.put(o(jSONObject.getJSONArray("CustomPurposesConsent"), Integer.valueOf(i)));
            editor.putString(str2, jSONArray.getString(jSONArray.length() - 1));
            if (z && z2) {
                editor.putString(OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESCONSENTS, jSONArray.getString(jSONArray.length() - 1));
            }
            jSONArray.put(o(jSONObject.getJSONArray("CustomPurposesLITransparency"), Integer.valueOf(i)));
            editor.putString(str, jSONArray.getString(jSONArray.length() - 1));
            if (z && z2) {
                editor.putString(OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESLEGITIMATEINTERESTS, jSONArray.getString(jSONArray.length() - 1));
            }
        } else {
            editor.putString(str2, "");
            editor.putString(str, "");
            if (z && z2) {
                editor.putString(OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESCONSENTS, "");
                editor.putString(OTIABTCFKeys.IABTCF_PUBLISHERCUSTOMPURPOSESLEGITIMATEINTERESTS, "");
            }
        }
        return e(jSONArray.toString().replace(",", "").replace("\"", "").replace("[", "").replace("]", ""));
    }

    public static JSONObject q(Context context) throws JSONException {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
        JSONObject jSONObject = new JSONObject();
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
            z = false;
        }
        new com.onetrust.otpublishers.headless.gpp.b(context);
        if (z) {
            sharedPreferences = fVar;
        }
        try {
        } catch (JSONException e) {
            Z.p("error while getting all string : ", e, "TCF2Encoder", 6);
        }
        if (sharedPreferences.getBoolean("OT_GPP_IS_ENABLED", false)) {
            return j(context, defaultSharedPreferences);
        }
        Iterator it2 = c.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            if (str.endsWith(".int")) {
                String strReplace = str.replace(".int", "");
                jSONObject.put(strReplace, defaultSharedPreferences.getInt(strReplace, -1));
            } else if (str.endsWith(".string")) {
                String strReplace2 = str.replace(".string", "");
                jSONObject.put(strReplace2, defaultSharedPreferences.getString(strReplace2, ""));
            }
        }
        return jSONObject;
    }

    public static void r(Context context) {
        int iD;
        String str;
        com.onetrust.otpublishers.headless.Internal.Preferences.a aVar = new com.onetrust.otpublishers.headless.Internal.Preferences.a(context);
        aVar.a(aVar.d("IABTCF_gdprApplies"), OTGppKeys.IAB_GPP_GDPRAPPLIES);
        aVar.a(aVar.d("IABTCF_CmpSdkID"), OTGppKeys.IAB_GPP_CMPSDKID);
        aVar.a(aVar.d(OTIABTCFKeys.IABTCF_CMPSDKVERSION), OTGppKeys.IAB_GPP_CMPSDKVERSION);
        aVar.a(aVar.d(OTIABTCFKeys.IABTCF_POLICYVERSION), OTGppKeys.IAB_GPP_POLICYVERSION);
        if (d) {
            iD = aVar.d(OTIABTCFKeys.IABTCF_USENONSTANDARDTEXTS);
            str = OTGppKeys.IAB_GPP_USENONSTANDARDTEXTS;
        } else {
            iD = aVar.d(OTIABTCFKeys.IABTCF_USENONSTANDARDSTACKS);
            str = OTGppKeys.IAB_GPP_USENONSTANDARDSTACKS;
        }
        aVar.a(iD, str);
        aVar.c(OTGppKeys.IAB_GPP_SPECIALFEATURESOPTINS, aVar.e(OTIABTCFKeys.IABTCF_SPECIALFEATURESOPTINS));
        aVar.c(OTGppKeys.IAB_GPP_TCFEU2_STRING, aVar.e("IABTCF_TCString"));
        aVar.c(OTGppKeys.IAB_GPP_PURPOSECONSENTS, aVar.e("IABTCF_PurposeConsents"));
        aVar.c(OTGppKeys.IAB_GPP_PUBLISHERCONSENT, aVar.e(OTIABTCFKeys.IABTCF_PUBLISHERCONSENT));
        aVar.c(OTGppKeys.IAB_GPP_PURPOSELEGITIMATEINTERESTS, aVar.e(OTIABTCFKeys.IABTCF_PURPOSELEGITIMATEINTERESTS));
        aVar.c(OTGppKeys.IAB_GPP_PUBLISHERLEGITIMATEINTERESTS, aVar.e(OTIABTCFKeys.IABTCF_PUBLISHERLEGITIMATEINTERESTS));
        aVar.a(aVar.d("IABTCF_PurposeOneTreatment"), OTGppKeys.IAB_GPP_PURPOSEONETREATMENT);
        aVar.c(OTGppKeys.IAB_GPP_PUBLISHERCC, aVar.e("IABTCF_PublisherCC"));
        aVar.c(OTGppKeys.IAB_GPP_VENDORCONSENTS, aVar.e("IABTCF_VendorConsents"));
        aVar.c(OTGppKeys.IAB_GPP_VENDORLEGITIMATEINTERESTS, aVar.e("IABTCF_VendorLegitimateInterests"));
        for (int i = 1; i <= 10; i++) {
            String strF = android.support.v4.media.session.a.f(i, OTIABTCFKeys.IABTCF_PUBLISHERRESTRICTIONS);
            if (aVar.a.contains(strF)) {
                aVar.c(android.support.v4.media.session.a.f(i, OTGppKeys.IAB_GPP_PUBLISHERRESTRICTIONS), aVar.e(strF));
            }
        }
    }

    public static void s(String str, Bundle adInfoBundle) {
        Intrinsics.checkNotNullParameter(adInfoBundle, "adInfoBundle");
        if (str == null || !StringsKt.G(str, "amzn.dtb.loadAd", false)) {
            return;
        }
        Matcher matcher = Pattern.compile("amzn.dtb.loadAd\\(\\\"(.*)\\\", \\\"(.*)\\\", \\\"(.*)\\\".*isv: (\\w+)").matcher(str);
        if (matcher.find() && matcher.groupCount() == 4) {
            adInfoBundle.putString("event_server_parameter", matcher.group(1));
            adInfoBundle.putString("bid_identifier", matcher.group(2));
            adInfoBundle.putString("hostname_identifier", matcher.group(3));
            adInfoBundle.putBoolean("video_flag", Boolean.parseBoolean(matcher.group(4)));
        }
    }

    public static D v(DBGroupFolder local) {
        Intrinsics.checkNotNullParameter(local, "local");
        return new D(Long.valueOf(local.getLocalId()), local.getClassId(), local.getFolderId(), local.getCanEdit(), local.getTimestamp(), Boolean.valueOf(local.getDeleted()), Long.valueOf(local.getClientTimestamp()), local.getLastModified(), local.getDirty());
    }

    public static void w() {
        File[] fileArrListFiles;
        if (J.B()) {
            return;
        }
        File fileD = G2.d();
        if (fileD == null) {
            fileArrListFiles = new File[0];
        } else {
            fileArrListFiles = fileD.listFiles(new H(1));
            if (fileArrListFiles == null) {
                fileArrListFiles = new File[0];
            }
        }
        ArrayList arrayList = new ArrayList(fileArrListFiles.length);
        for (File file : fileArrListFiles) {
            arrayList.add(F2.d(file));
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (((com.facebook.internal.instrument.c) next).a()) {
                arrayList2.add(next);
            }
        }
        List listN0 = CollectionsKt.n0(arrayList2, new a0(12));
        JSONArray jSONArray = new JSONArray();
        kotlin.ranges.i it3 = kotlin.ranges.l.h(0, Math.min(listN0.size(), 5)).iterator();
        while (it3.c) {
            jSONArray.put(listN0.get(it3.nextInt()));
        }
        G2.h("crash_reports", jSONArray, new com.facebook.internal.instrument.anrreport.b(listN0, 1));
    }

    public static com.quizlet.assembly.compose.menu.r x() {
        com.quizlet.themes.m dimens = com.quizlet.themes.m.g;
        Intrinsics.checkNotNullParameter(dimens, "dimens");
        dimens.s();
        float f = -com.quizlet.ui.resources.designsystem.generated.j.h;
        dimens.r();
        return new com.quizlet.assembly.compose.menu.r(new com.quizlet.assembly.compose.menu.t(N5.b(f, com.quizlet.ui.resources.designsystem.generated.j.e)));
    }

    @Override // com.google.gson.internal.n
    public Object E() {
        return new ArrayDeque();
    }

    @Override // com.bumptech.glide.util.pool.a
    public Object c() {
        switch (this.a) {
            case 6:
                try {
                    return new com.bumptech.glide.load.engine.cache.g(MessageDigest.getInstance("SHA-256"));
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            default:
                return new ArrayList();
        }
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        return new com.google.mlkit.vision.barcode.internal.b((com.google.mlkit.vision.barcode.internal.d) c0Var.get(com.google.mlkit.vision.barcode.internal.d.class), (com.google.mlkit.common.sdkinternal.d) c0Var.get(com.google.mlkit.common.sdkinternal.d.class), (com.google.mlkit.common.sdkinternal.f) c0Var.get(com.google.mlkit.common.sdkinternal.f.class));
    }

    @Override // com.quizlet.local.ormlite.util.c
    public ArrayList g(List list) {
        return AbstractC3771z.c(this, list);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public /* bridge */ /* synthetic */ Object h(Object obj) {
        return v((DBGroupFolder) obj);
    }

    /* JADX WARN: Removed duplicated region for block: B:57:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0103  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String t(android.content.Context r22, android.os.Bundle r23) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 294
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.h.t(android.content.Context, android.os.Bundle):java.lang.String");
    }

    public void u(Context context, boolean z, String name, StringBuilder sb) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(sb, "sb");
        if (!z) {
            try {
                String strLoadFile = WebResourceService.getInstance().loadFile(name);
                if (strLoadFile != null) {
                    sb.append("<script>");
                    sb.append(strLoadFile);
                    sb.append("</script>");
                    return;
                }
            } catch (Exception unused) {
                AbstractC3538u.b(this, "Failed to read local file");
            }
        }
        sb.append("<script>");
        try {
            InputStream inputStreamOpen = context.getAssets().open(Intrinsics.k(".js", name));
            Intrinsics.checkNotNullExpressionValue(inputStreamOpen, "context.assets.open(\"$name.js\")");
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStreamOpen));
            while (true) {
                String line = bufferedReader.readLine();
                if (line == null) {
                    break;
                }
                sb.append(StringsKt.g0(line).toString());
                sb.append("\n");
            }
            bufferedReader.close();
            inputStreamOpen.close();
        } catch (Exception unused2) {
            AbstractC3538u.b(this, Intrinsics.k(name, "Error reading file:"));
        }
        sb.append("</script>");
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 10:
                List list = AbstractC3893t.a;
                Boolean bool = (Boolean) A3.a.b();
                bool.getClass();
                return bool;
            case 11:
                List list2 = AbstractC3893t.a;
                W3.b.get();
                Boolean bool2 = (Boolean) Y3.a.b();
                bool2.getClass();
                return bool2;
            case 12:
                Boolean bool3 = (Boolean) W2.a.b();
                bool3.getClass();
                return bool3;
            case 13:
                List list3 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.K.b();
            case 14:
                List list4 = AbstractC3893t.a;
                E3.b.get();
                Boolean bool4 = (Boolean) G3.e.b();
                bool4.getClass();
                return bool4;
            case 15:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.r.b()).longValue());
            case 16:
                List list6 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.b0.b();
                l.getClass();
                return l;
            default:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.T.b()).longValue());
        }
    }
}
