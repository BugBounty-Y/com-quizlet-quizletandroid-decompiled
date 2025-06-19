package com.google.android.gms.measurement.internal;

import android.content.SharedPreferences;
import android.text.TextUtils;
import com.google.android.gms.internal.measurement.H1;
import com.google.android.gms.internal.measurement.I1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3531s4;
import com.google.common.collect.C3922e;

/* loaded from: classes2.dex */
public abstract class j1 {
    public static final com.google.common.collect.x a;

    static {
        C3922e c3922e = com.google.common.collect.j.b;
        Object[] objArr = new Object[24];
        objArr[0] = "Version";
        objArr[1] = "GoogleConsent";
        objArr[2] = "VendorConsent";
        objArr[3] = "VendorLegitimateInterest";
        objArr[4] = "gdprApplies";
        objArr[5] = "EnableAdvertiserConsentMode";
        objArr[6] = "PolicyVersion";
        objArr[7] = "PurposeConsents";
        objArr[8] = "PurposeOneTreatment";
        objArr[9] = "Purpose1";
        objArr[10] = "Purpose3";
        objArr[11] = "Purpose4";
        System.arraycopy(new String[]{"Purpose7", "CmpSdkID", "PublisherCC", "PublisherRestrictions1", "PublisherRestrictions3", "PublisherRestrictions4", "PublisherRestrictions7", "AuthorizePurpose1", "AuthorizePurpose3", "AuthorizePurpose4", "AuthorizePurpose7", "PurposeDiagnostics"}, 0, objArr, 12, 12);
        AbstractC3531s4.e(24, objArr);
        a = com.google.common.collect.j.k(24, objArr);
    }

    public static int a(SharedPreferences sharedPreferences, String str) {
        try {
            return sharedPreferences.getInt(str, -1);
        } catch (ClassCastException unused) {
            return -1;
        }
    }

    public static String b(SharedPreferences sharedPreferences, String str) {
        try {
            return sharedPreferences.getString(str, "");
        } catch (ClassCastException unused) {
            return "";
        }
    }

    public static final boolean c(H1 h1, com.google.common.collect.C c, com.google.common.collect.C c2, com.google.common.collect.E e, char[] cArr, int i, int i2, int i3, String str, String str2, String str3, boolean z, boolean z2) {
        i1 i1Var;
        char c3;
        int iD = d(h1);
        if (iD > 0 && (i2 != 1 || i != 1)) {
            cArr[iD] = '2';
        }
        if (e(h1, c2) == I1.PURPOSE_RESTRICTION_NOT_ALLOWED) {
            c3 = '3';
        } else {
            if (h1 == H1.IAB_TCF_PURPOSE_STORE_AND_ACCESS_INFORMATION_ON_A_DEVICE && i3 == 1 && e.d.equals(str)) {
                if (iD > 0 && cArr[iD] != '2') {
                    cArr[iD] = '1';
                }
                return true;
            }
            if (c.containsKey(h1) && (i1Var = (i1) c.get(h1)) != null) {
                int iOrdinal = i1Var.ordinal();
                I1 i1 = I1.PURPOSE_RESTRICTION_REQUIRE_LEGITIMATE_INTEREST;
                if (iOrdinal != 0) {
                    I1 i12 = I1.PURPOSE_RESTRICTION_REQUIRE_CONSENT;
                    if (iOrdinal != 1) {
                        if (iOrdinal == 2) {
                            return e(h1, c2) == i1 ? h(h1, cArr, str3, z2) : g(h1, cArr, str2, z);
                        }
                        if (iOrdinal == 3) {
                            return e(h1, c2) == i12 ? g(h1, cArr, str2, z) : h(h1, cArr, str3, z2);
                        }
                        c3 = '0';
                    } else if (e(h1, c2) != i12) {
                        return h(h1, cArr, str3, z2);
                    }
                } else if (e(h1, c2) != i1) {
                    return g(h1, cArr, str2, z);
                }
                c3 = '8';
            } else {
                c3 = '0';
            }
        }
        if (iD <= 0 || cArr[iD] == '2') {
            return false;
        }
        cArr[iD] = c3;
        return false;
    }

    public static final int d(H1 h1) {
        if (h1 == H1.IAB_TCF_PURPOSE_STORE_AND_ACCESS_INFORMATION_ON_A_DEVICE) {
            return 1;
        }
        if (h1 == H1.IAB_TCF_PURPOSE_CREATE_A_PERSONALISED_ADS_PROFILE) {
            return 2;
        }
        if (h1 == H1.IAB_TCF_PURPOSE_SELECT_PERSONALISED_ADS) {
            return 3;
        }
        return h1 == H1.IAB_TCF_PURPOSE_MEASURE_AD_PERFORMANCE ? 4 : -1;
    }

    public static final I1 e(H1 h1, com.google.common.collect.C c) {
        Object obj = I1.PURPOSE_RESTRICTION_UNDEFINED;
        Object obj2 = c.get(h1);
        if (obj2 != null) {
            obj = obj2;
        }
        return (I1) obj;
    }

    public static final String f(H1 h1, String str, String str2) {
        String strValueOf = "0";
        String strValueOf2 = (TextUtils.isEmpty(str) || str.length() < h1.a()) ? "0" : String.valueOf(str.charAt(h1.a() - 1));
        if (!TextUtils.isEmpty(str2) && str2.length() >= h1.a()) {
            strValueOf = String.valueOf(str2.charAt(h1.a() - 1));
        }
        return String.valueOf(strValueOf2).concat(String.valueOf(strValueOf));
    }

    public static final boolean g(H1 h1, char[] cArr, String str, boolean z) {
        char c;
        int iD = d(h1);
        if (!z) {
            c = '4';
        } else {
            if (str.length() >= h1.a()) {
                char cCharAt = str.charAt(h1.a() - 1);
                boolean z2 = cCharAt == '1';
                if (iD > 0 && cArr[iD] != '2') {
                    cArr[iD] = cCharAt != '1' ? '6' : '1';
                }
                return z2;
            }
            c = '0';
        }
        if (iD > 0 && cArr[iD] != '2') {
            cArr[iD] = c;
        }
        return false;
    }

    public static final boolean h(H1 h1, char[] cArr, String str, boolean z) {
        char c;
        int iD = d(h1);
        if (!z) {
            c = '5';
        } else {
            if (str.length() >= h1.a()) {
                char cCharAt = str.charAt(h1.a() - 1);
                boolean z2 = cCharAt == '1';
                if (iD > 0 && cArr[iD] != '2') {
                    cArr[iD] = cCharAt != '1' ? '7' : '1';
                }
                return z2;
            }
            c = '0';
        }
        if (iD > 0 && cArr[iD] != '2') {
            cArr[iD] = c;
        }
        return false;
    }
}
