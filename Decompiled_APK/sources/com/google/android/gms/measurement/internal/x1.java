package com.google.android.gms.measurement.internal;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.content.pm.Signature;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import android.text.TextUtils;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.j256.ormlite.field.FieldType;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicLong;
import javax.security.auth.x500.X500Principal;

/* loaded from: classes2.dex */
public final class x1 extends AbstractC3871h0 {
    public static final String[] j = {"firebase_", "google_", "ga_"};
    public static final String[] k = {"_err"};
    public SecureRandom d;
    public final AtomicLong e;
    public int f;
    public androidx.privacysandbox.ads.adservices.java.measurement.h g;
    public Boolean h;
    public Integer i;

    public x1(Y y) {
        super(y);
        this.i = null;
        this.e = new AtomicLong(0L);
    }

    public static boolean I0(Object obj) {
        return (obj instanceof Parcelable[]) || (obj instanceof ArrayList) || (obj instanceof Bundle);
    }

    public static boolean L0(String str) {
        return !TextUtils.isEmpty(str) && str.startsWith("_");
    }

    public static boolean M0(String str) {
        com.google.android.gms.common.internal.u.e(str);
        return str.charAt(0) != '_' || str.equals("_ep");
    }

    public static boolean N0(Context context) {
        ActivityInfo receiverInfo;
        com.google.android.gms.common.internal.u.h(context);
        try {
            PackageManager packageManager = context.getPackageManager();
            if (packageManager != null && (receiverInfo = packageManager.getReceiverInfo(new ComponentName(context, "com.google.android.gms.measurement.AppMeasurementReceiver"), 0)) != null) {
                if (receiverInfo.enabled) {
                    return true;
                }
            }
        } catch (PackageManager.NameNotFoundException unused) {
        }
        return false;
    }

    public static boolean O0(Context context) {
        ServiceInfo serviceInfo;
        try {
            PackageManager packageManager = context.getPackageManager();
            if (packageManager != null && (serviceInfo = packageManager.getServiceInfo(new ComponentName(context, "com.google.android.gms.measurement.AppMeasurementJobService"), 0)) != null) {
                if (serviceInfo.enabled) {
                    return true;
                }
            }
        } catch (PackageManager.NameNotFoundException unused) {
        }
        return false;
    }

    public static byte[] R0(Parcelable parcelable) {
        if (parcelable == null) {
            return null;
        }
        Parcel parcelObtain = Parcel.obtain();
        try {
            parcelable.writeToParcel(parcelObtain, 0);
            return parcelObtain.marshall();
        } finally {
            parcelObtain.recycle();
        }
    }

    public static final boolean S0(int i, Bundle bundle) {
        if (bundle == null || bundle.getLong("_err") != 0) {
            return false;
        }
        bundle.putLong("_err", i);
        return true;
    }

    public static long a1(byte[] bArr) {
        com.google.android.gms.common.internal.u.h(bArr);
        int length = bArr.length;
        int i = 0;
        com.google.android.gms.common.internal.u.k(length > 0);
        long j2 = 0;
        for (int i2 = length - 1; i2 >= 0 && i2 >= bArr.length - 8; i2--) {
            j2 += (bArr[i2] & 255) << i;
            i += 8;
        }
        return j2;
    }

    public static String b0(String str, int i, boolean z) {
        if (str != null) {
            if (str.codePointCount(0, str.length()) <= i) {
                return str;
            }
            if (z) {
                return String.valueOf(str.substring(0, str.offsetByCodePoints(0, i))).concat("...");
            }
        }
        return null;
    }

    public static MessageDigest c0() throws NoSuchAlgorithmException {
        MessageDigest messageDigest;
        for (int i = 0; i < 2; i++) {
            try {
                messageDigest = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException unused) {
            }
            if (messageDigest != null) {
                return messageDigest;
            }
        }
        return null;
    }

    public static ArrayList e0(List list) {
        if (list == null) {
            return new ArrayList(0);
        }
        ArrayList arrayList = new ArrayList(list.size());
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            zzai zzaiVar = (zzai) it2.next();
            Bundle bundle = new Bundle();
            bundle.putString("app_id", zzaiVar.a);
            bundle.putString("origin", zzaiVar.b);
            bundle.putLong("creation_timestamp", zzaiVar.d);
            bundle.putString("name", zzaiVar.c.b);
            Object objA = zzaiVar.c.a();
            com.google.android.gms.common.internal.u.h(objA);
            AbstractC3883n0.e(bundle, objA);
            bundle.putBoolean("active", zzaiVar.e);
            String str = zzaiVar.f;
            if (str != null) {
                bundle.putString("trigger_event_name", str);
            }
            zzbh zzbhVar = zzaiVar.g;
            if (zzbhVar != null) {
                bundle.putString("timed_out_event_name", zzbhVar.a);
                zzbf zzbfVar = zzbhVar.b;
                if (zzbfVar != null) {
                    bundle.putBundle("timed_out_event_params", zzbfVar.a());
                }
            }
            bundle.putLong("trigger_timeout", zzaiVar.h);
            zzbh zzbhVar2 = zzaiVar.i;
            if (zzbhVar2 != null) {
                bundle.putString("triggered_event_name", zzbhVar2.a);
                zzbf zzbfVar2 = zzbhVar2.b;
                if (zzbfVar2 != null) {
                    bundle.putBundle("triggered_event_params", zzbfVar2.a());
                }
            }
            bundle.putLong("triggered_timestamp", zzaiVar.c.c);
            bundle.putLong("time_to_live", zzaiVar.j);
            zzbh zzbhVar3 = zzaiVar.k;
            if (zzbhVar3 != null) {
                bundle.putString("expired_event_name", zzbhVar3.a);
                zzbf zzbfVar3 = zzbhVar3.b;
                if (zzbfVar3 != null) {
                    bundle.putBundle("expired_event_params", zzbfVar3.a());
                }
            }
            arrayList.add(bundle);
        }
        return arrayList;
    }

    public static void h0(L0 l0, Bundle bundle, boolean z) {
        if (bundle != null && l0 != null) {
            if (!bundle.containsKey("_sc") || z) {
                String str = l0.a;
                if (str != null) {
                    bundle.putString("_sn", str);
                } else {
                    bundle.remove("_sn");
                }
                String str2 = l0.b;
                if (str2 != null) {
                    bundle.putString("_sc", str2);
                } else {
                    bundle.remove("_sc");
                }
                bundle.putLong("_si", l0.c);
                return;
            }
            z = false;
        }
        if (bundle != null && l0 == null && z) {
            bundle.remove("_sn");
            bundle.remove("_sc");
            bundle.remove("_si");
        }
    }

    public static void l0(w1 w1Var, String str, int i, String str2, String str3, int i2) {
        Bundle bundle = new Bundle();
        S0(i, bundle);
        if (!TextUtils.isEmpty(str2) && !TextUtils.isEmpty(str3)) {
            bundle.putString(str2, str3);
        }
        if (i == 6 || i == 7 || i == 2) {
            bundle.putLong("_el", i2);
        }
        w1Var.g(str, "_err", bundle);
    }

    public static boolean x0(String str, String[] strArr) {
        com.google.android.gms.common.internal.u.h(strArr);
        for (String str2 : strArr) {
            if (Objects.equals(str, str2)) {
                return true;
            }
        }
        return false;
    }

    public static boolean z0(String str) {
        String str2 = (String) AbstractC3893t.q0.a(null);
        return str2.equals("*") || Arrays.asList(str2.split(",")).contains(str);
    }

    public final boolean A0(String str, String str2) {
        Y y = (Y) this.b;
        boolean zF0 = y.g.f0(null, AbstractC3893t.p1);
        String str3 = y.b;
        I i = y.i;
        if (zF0) {
            if (TextUtils.isEmpty(str)) {
                if (TextUtils.isEmpty(str3)) {
                    Y.k(i);
                    i.i.f("Missing google_app_id. Firebase Analytics disabled. See https://goo.gl/NAOOOI");
                    return false;
                }
            } else {
                if (Q0(str)) {
                    return true;
                }
                if (TextUtils.isEmpty(str3)) {
                    Y.k(i);
                    i.i.g("Invalid google_app_id. Firebase Analytics disabled. See https://goo.gl/NAOOOI. provided id", I.a0(str));
                    return false;
                }
            }
        } else if (TextUtils.isEmpty(str)) {
            if (!TextUtils.isEmpty(str2)) {
                if (Q0(str2)) {
                    return true;
                }
                Y.k(i);
                i.i.g("Invalid admob_app_id. Analytics disabled.", I.a0(str2));
                return false;
            }
            if (TextUtils.isEmpty(str3)) {
                Y.k(i);
                i.i.f("Missing google_app_id. Firebase Analytics disabled. See https://goo.gl/NAOOOI");
            }
        } else {
            if (Q0(str)) {
                return true;
            }
            if (TextUtils.isEmpty(str3)) {
                Y.k(i);
                i.i.g("Invalid google_app_id. Firebase Analytics disabled. See https://goo.gl/NAOOOI. provided id", I.a0(str));
                return false;
            }
        }
        return false;
    }

    public final boolean B0(int i, String str, String str2) {
        Y y = (Y) this.b;
        if (str2 == null) {
            I i2 = y.i;
            Y.k(i2);
            i2.i.g("Name is required and can't be null. Type", str);
            return false;
        }
        if (str2.codePointCount(0, str2.length()) <= i) {
            return true;
        }
        I i3 = y.i;
        Y.k(i3);
        i3.i.i("Name is too long. Type, maximum supported length, name", str, Integer.valueOf(i), str2);
        return false;
    }

    public final boolean C0(String str, String[] strArr, String[] strArr2, String str2) {
        Y y = (Y) this.b;
        if (str2 == null) {
            I i = y.i;
            Y.k(i);
            i.i.g("Name is required and can't be null. Type", str);
            return false;
        }
        String[] strArr3 = j;
        for (int i2 = 0; i2 < 3; i2++) {
            if (str2.startsWith(strArr3[i2])) {
                I i3 = y.i;
                Y.k(i3);
                i3.i.h("Name starts with reserved prefix. Type, name", str, str2);
                return false;
            }
        }
        if (strArr == null || !x0(str2, strArr)) {
            return true;
        }
        if (strArr2 != null && x0(str2, strArr2)) {
            return true;
        }
        I i4 = y.i;
        Y.k(i4);
        i4.i.h("Name is reserved. Type, name", str, str2);
        return false;
    }

    public final boolean D0(String str, String str2, int i, Object obj) {
        if (obj == null || (obj instanceof Long) || (obj instanceof Float) || (obj instanceof Integer) || (obj instanceof Byte) || (obj instanceof Short) || (obj instanceof Boolean) || (obj instanceof Double)) {
            return true;
        }
        if (!(obj instanceof String) && !(obj instanceof Character) && !(obj instanceof CharSequence)) {
            return false;
        }
        String string = obj.toString();
        if (string.codePointCount(0, string.length()) > i) {
            I i2 = ((Y) this.b).i;
            Y.k(i2);
            i2.l.i("Value is too long; discarded. Value kind, name, value length", str, str2, Integer.valueOf(string.length()));
            return false;
        }
        return true;
    }

    public final boolean E0(String str, String str2) {
        Y y = (Y) this.b;
        if (str2 == null) {
            I i = y.i;
            Y.k(i);
            i.i.g("Name is required and can't be null. Type", str);
            return false;
        }
        if (str2.length() == 0) {
            I i2 = y.i;
            Y.k(i2);
            i2.i.g("Name is required and can't be empty. Type", str);
            return false;
        }
        int iCodePointAt = str2.codePointAt(0);
        if (!Character.isLetter(iCodePointAt)) {
            if (iCodePointAt != 95) {
                I i3 = y.i;
                Y.k(i3);
                i3.i.h("Name must start with a letter or _ (underscore). Type, name", str, str2);
                return false;
            }
            iCodePointAt = 95;
        }
        int length = str2.length();
        int iCharCount = Character.charCount(iCodePointAt);
        while (iCharCount < length) {
            int iCodePointAt2 = str2.codePointAt(iCharCount);
            if (iCodePointAt2 != 95 && !Character.isLetterOrDigit(iCodePointAt2)) {
                I i4 = y.i;
                Y.k(i4);
                i4.i.h("Name must consist of letters, digits or _ (underscores). Type, name", str, str2);
                return false;
            }
            iCharCount += Character.charCount(iCodePointAt2);
        }
        return true;
    }

    public final boolean F0(String str, String str2) {
        Y y = (Y) this.b;
        if (str2 == null) {
            I i = y.i;
            Y.k(i);
            i.i.g("Name is required and can't be null. Type", str);
            return false;
        }
        if (str2.length() == 0) {
            I i2 = y.i;
            Y.k(i2);
            i2.i.g("Name is required and can't be empty. Type", str);
            return false;
        }
        int iCodePointAt = str2.codePointAt(0);
        if (!Character.isLetter(iCodePointAt)) {
            I i3 = y.i;
            Y.k(i3);
            i3.i.h("Name must start with a letter. Type, name", str, str2);
            return false;
        }
        int length = str2.length();
        int iCharCount = Character.charCount(iCodePointAt);
        while (iCharCount < length) {
            int iCodePointAt2 = str2.codePointAt(iCharCount);
            if (iCodePointAt2 != 95 && !Character.isLetterOrDigit(iCodePointAt2)) {
                I i4 = y.i;
                Y.k(i4);
                i4.i.h("Name must consist of letters, digits or _ (underscores). Type, name", str, str2);
                return false;
            }
            iCharCount += Character.charCount(iCodePointAt2);
        }
        return true;
    }

    public final boolean G0(String str) {
        S();
        Y y = (Y) this.b;
        if (com.google.android.gms.common.wrappers.c.a(y.a).a.checkCallingOrSelfPermission(str) == 0) {
            return true;
        }
        I i = y.i;
        Y.k(i);
        i.n.g("Permission not granted", str);
        return false;
    }

    public final boolean H0(String str, String str2) {
        if (!TextUtils.isEmpty(str2)) {
            return true;
        }
        if (TextUtils.isEmpty(str)) {
            return false;
        }
        return ((Y) this.b).g.W("debug.firebase.analytics.app").equals(str);
    }

    public final boolean J0(Context context, String str) {
        Signature[] signatureArr;
        Y y = (Y) this.b;
        X500Principal x500Principal = new X500Principal("CN=Android Debug,O=Android,C=US");
        try {
            PackageInfo packageInfoC = com.google.android.gms.common.wrappers.c.a(context).c(str, 64);
            if (packageInfoC == null || (signatureArr = packageInfoC.signatures) == null || signatureArr.length <= 0) {
                return true;
            }
            return ((X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(signatureArr[0].toByteArray()))).getSubjectX500Principal().equals(x500Principal);
        } catch (PackageManager.NameNotFoundException e) {
            I i = y.i;
            Y.k(i);
            i.g.g("Package name not found", e);
            return true;
        } catch (CertificateException e2) {
            I i2 = y.i;
            Y.k(i2);
            i2.g.g("Error obtaining certificate", e2);
            return true;
        }
    }

    public final boolean K0(int i) {
        Boolean bool = ((Y) this.b).r().f;
        if (Y0() < i / 1000) {
            return (bool == null || bool.booleanValue()) ? false : true;
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x007f A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0080 A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean P0(java.lang.String r5, java.lang.String r6, java.lang.String r7, java.lang.String r8) {
        /*
            r4 = this;
            java.lang.Object r0 = r4.b
            com.google.android.gms.measurement.internal.Y r0 = (com.google.android.gms.measurement.internal.Y) r0
            com.google.android.gms.measurement.internal.e r0 = r0.g
            r1 = 0
            com.google.android.gms.measurement.internal.s r2 = com.google.android.gms.measurement.internal.AbstractC3893t.p1
            boolean r0 = r0.f0(r1, r2)
            r1 = 0
            r2 = 1
            if (r0 == 0) goto L28
            boolean r7 = android.text.TextUtils.isEmpty(r5)
            boolean r8 = android.text.TextUtils.isEmpty(r6)
            if (r7 != 0) goto L27
            if (r8 != 0) goto L27
            com.google.android.gms.common.internal.u.h(r5)
            boolean r5 = r5.equals(r6)
            if (r5 != 0) goto L27
            return r2
        L27:
            return r1
        L28:
            boolean r0 = android.text.TextUtils.isEmpty(r5)
            boolean r3 = android.text.TextUtils.isEmpty(r6)
            if (r0 != 0) goto L3e
            if (r3 != 0) goto L3e
            com.google.android.gms.common.internal.u.h(r5)
            boolean r5 = r5.equals(r6)
            if (r5 != 0) goto L7f
            goto L80
        L3e:
            if (r0 == 0) goto L5c
            if (r3 == 0) goto L5c
            boolean r5 = android.text.TextUtils.isEmpty(r7)
            if (r5 != 0) goto L55
            boolean r5 = android.text.TextUtils.isEmpty(r8)
            if (r5 != 0) goto L55
            boolean r5 = r7.equals(r8)
            if (r5 != 0) goto L7f
            goto L80
        L55:
            boolean r5 = android.text.TextUtils.isEmpty(r8)
            if (r5 != 0) goto L7f
            goto L80
        L5c:
            if (r0 != 0) goto L72
            boolean r5 = android.text.TextUtils.isEmpty(r8)
            if (r5 == 0) goto L65
            goto L7f
        L65:
            boolean r5 = android.text.TextUtils.isEmpty(r7)
            if (r5 != 0) goto L80
            boolean r5 = r7.equals(r8)
            if (r5 != 0) goto L7f
            goto L80
        L72:
            boolean r5 = android.text.TextUtils.isEmpty(r7)
            if (r5 != 0) goto L80
            boolean r5 = r7.equals(r8)
            if (r5 != 0) goto L7f
            goto L80
        L7f:
            return r1
        L80:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.x1.P0(java.lang.String, java.lang.String, java.lang.String, java.lang.String):boolean");
    }

    public final boolean Q0(String str) {
        com.google.android.gms.common.internal.u.h(str);
        return str.matches(true != ((Y) this.b).g.f0(null, AbstractC3893t.p1) ? "^(1:\\d+:android:[a-f0-9]+|ca-app-pub-.*)$" : "^1:\\d+:android:[a-f0-9]+$");
    }

    @Override // com.google.android.gms.measurement.internal.AbstractC3871h0
    public final boolean T() {
        return true;
    }

    public final int T0(Object obj, String str) {
        return "_ldl".equals(str) ? D0("user property referrer", str, v0(str), obj) : D0("user property", str, v0(str), obj) ? 0 : 7;
    }

    public final int U0(String str) {
        if (!E0("event", str)) {
            return 2;
        }
        if (!C0("event", AbstractC3883n0.a, AbstractC3883n0.b, str)) {
            return 13;
        }
        ((Y) this.b).getClass();
        return !B0(40, "event", str) ? 2 : 0;
    }

    public final int V0(String str) {
        if (!E0("event param", str)) {
            return 3;
        }
        if (!C0("event param", null, null, str)) {
            return 14;
        }
        ((Y) this.b).getClass();
        return !B0(40, "event param", str) ? 3 : 0;
    }

    public final Bundle W(String str, Bundle bundle, List list, boolean z) {
        int iW0;
        List list2 = list;
        boolean zX0 = x0(str, AbstractC3883n0.d);
        if (bundle == null) {
            return null;
        }
        Bundle bundle2 = new Bundle(bundle);
        Y y = (Y) this.b;
        x1 x1Var = ((Y) y.g.b).l;
        Y.h(x1Var);
        int i = x1Var.K0(201500000) ? 100 : 25;
        Iterator it2 = new TreeSet(bundle.keySet()).iterator();
        int i2 = 0;
        boolean z2 = false;
        while (it2.hasNext()) {
            String str2 = (String) it2.next();
            if (list2 == null || !list2.contains(str2)) {
                iW0 = !z ? W0(str2) : 0;
                if (iW0 == 0) {
                    iW0 = V0(str2);
                }
            } else {
                iW0 = 0;
            }
            if (iW0 != 0) {
                g0(bundle2, iW0, str2, iW0 == 3 ? str2 : null);
                bundle2.remove(str2);
            } else {
                int iU0 = u0(str, str2, bundle.get(str2), bundle2, list2, z, zX0);
                if (iU0 == 17) {
                    g0(bundle2, 17, str2, Boolean.FALSE);
                } else if (iU0 != 0 && !"_ev".equals(str2)) {
                    g0(bundle2, iU0, iU0 == 21 ? str : str2, bundle.get(str2));
                    bundle2.remove(str2);
                }
                if (M0(str2) && (i2 = i2 + 1) > i) {
                    if (!y.g.f0(null, AbstractC3893t.r1) || !z2) {
                        String strC = AbstractC0147y.c(i, "Event can't contain more than ", " params");
                        I i3 = y.i;
                        Y.k(i3);
                        D d = y.m;
                        i3.i.h(strC, d.d(str), d.b(bundle));
                    }
                    S0(5, bundle2);
                    bundle2.remove(str2);
                    z2 = true;
                }
            }
            list2 = list;
        }
        return bundle2;
    }

    public final int W0(String str) {
        if (!F0("event param", str)) {
            return 3;
        }
        if (!C0("event param", null, null, str)) {
            return 14;
        }
        ((Y) this.b).getClass();
        return !B0(40, "event param", str) ? 3 : 0;
    }

    public final zzbh X(String str, Bundle bundle, String str2, long j2, boolean z) {
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        if (U0(str) != 0) {
            Y y = (Y) this.b;
            I i = y.i;
            Y.k(i);
            i.g.g("Invalid conditional property event name", y.m.f(str));
            throw new IllegalArgumentException();
        }
        Bundle bundle2 = bundle != null ? new Bundle(bundle) : new Bundle();
        bundle2.putString("_o", str2);
        Bundle bundleW = W(str, bundle2, Collections.singletonList("_o"), true);
        if (z) {
            bundleW = d1(bundleW);
        }
        com.google.android.gms.common.internal.u.h(bundleW);
        return new zzbh(str, new zzbf(bundleW), str2, j2);
    }

    public final int X0(String str) {
        if (!E0("user property", str)) {
            return 6;
        }
        if (!C0("user property", AbstractC3883n0.i, null, str)) {
            return 15;
        }
        ((Y) this.b).getClass();
        return !B0(24, "user property", str) ? 6 : 0;
    }

    public final Object Y(Object obj, String str) {
        boolean zEquals = "_ev".equals(str);
        int iMax = com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR;
        Y y = (Y) this.b;
        if (zEquals) {
            y.g.getClass();
            return w0(Math.max(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR, 256), obj, true, true);
        }
        if (L0(str)) {
            y.g.getClass();
            iMax = Math.max(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR, 256);
        } else {
            y.g.getClass();
        }
        return w0(iMax, obj, false, true);
    }

    public final int Y0() {
        if (this.i == null) {
            com.google.android.gms.common.c cVar = com.google.android.gms.common.c.b;
            Context context = ((Y) this.b).a;
            cVar.getClass();
            this.i = Integer.valueOf(com.google.android.gms.common.c.a(context) / 1000);
        }
        return this.i.intValue();
    }

    public final Object Z(Object obj, String str) {
        return "_ldl".equals(str) ? w0(v0(str), obj, true, false) : w0(v0(str), obj, false, false);
    }

    /* JADX WARN: Removed duplicated region for block: B:62:0x00c8  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00ce A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00d1 A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long Z0() {
        /*
            Method dump skipped, instructions count: 210
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.x1.Z0():long");
    }

    public final String a0() {
        byte[] bArr = new byte[16];
        d0().nextBytes(bArr);
        return String.format(Locale.US, "%032x", new BigInteger(1, bArr));
    }

    public final long b1() {
        long andIncrement;
        long j2;
        AtomicLong atomicLong = this.e;
        if (atomicLong.get() != 0) {
            AtomicLong atomicLong2 = this.e;
            synchronized (atomicLong2) {
                atomicLong2.compareAndSet(-1L, 1L);
                andIncrement = atomicLong2.getAndIncrement();
            }
            return andIncrement;
        }
        synchronized (atomicLong) {
            long jNanoTime = System.nanoTime();
            ((Y) this.b).n.getClass();
            long jNextLong = new Random(jNanoTime ^ System.currentTimeMillis()).nextLong();
            int i = this.f + 1;
            this.f = i;
            j2 = jNextLong + i;
        }
        return j2;
    }

    public final Bundle c1(Uri uri) {
        String queryParameter;
        String queryParameter2;
        String queryParameter3;
        String queryParameter4;
        String queryParameter5;
        String queryParameter6;
        String queryParameter7;
        String queryParameter8;
        String queryParameter9;
        String str;
        if (uri == null) {
            return null;
        }
        try {
            if (uri.isHierarchical()) {
                queryParameter = uri.getQueryParameter("utm_campaign");
                queryParameter2 = uri.getQueryParameter("utm_source");
                queryParameter3 = uri.getQueryParameter("utm_medium");
                queryParameter4 = uri.getQueryParameter("gclid");
                queryParameter5 = uri.getQueryParameter("gbraid");
                queryParameter6 = uri.getQueryParameter("utm_id");
                queryParameter7 = uri.getQueryParameter("dclid");
                queryParameter8 = uri.getQueryParameter("srsltid");
                queryParameter9 = uri.getQueryParameter("sfmc_id");
            } else {
                queryParameter = null;
                queryParameter2 = null;
                queryParameter3 = null;
                queryParameter4 = null;
                queryParameter5 = null;
                queryParameter6 = null;
                queryParameter7 = null;
                queryParameter8 = null;
                queryParameter9 = null;
            }
            if (TextUtils.isEmpty(queryParameter) && TextUtils.isEmpty(queryParameter2) && TextUtils.isEmpty(queryParameter3) && TextUtils.isEmpty(queryParameter4) && TextUtils.isEmpty(queryParameter5) && TextUtils.isEmpty(queryParameter6) && TextUtils.isEmpty(queryParameter7) && TextUtils.isEmpty(queryParameter8) && TextUtils.isEmpty(queryParameter9)) {
                return null;
            }
            Bundle bundle = new Bundle();
            if (TextUtils.isEmpty(queryParameter)) {
                str = "sfmc_id";
            } else {
                str = "sfmc_id";
                bundle.putString("campaign", queryParameter);
            }
            if (!TextUtils.isEmpty(queryParameter2)) {
                bundle.putString("source", queryParameter2);
            }
            if (!TextUtils.isEmpty(queryParameter3)) {
                bundle.putString("medium", queryParameter3);
            }
            if (!TextUtils.isEmpty(queryParameter4)) {
                bundle.putString("gclid", queryParameter4);
            }
            if (!TextUtils.isEmpty(queryParameter5)) {
                bundle.putString("gbraid", queryParameter5);
            }
            String queryParameter10 = uri.getQueryParameter("gad_source");
            if (!TextUtils.isEmpty(queryParameter10)) {
                bundle.putString("gad_source", queryParameter10);
            }
            String queryParameter11 = uri.getQueryParameter("utm_term");
            if (!TextUtils.isEmpty(queryParameter11)) {
                bundle.putString("term", queryParameter11);
            }
            String queryParameter12 = uri.getQueryParameter("utm_content");
            if (!TextUtils.isEmpty(queryParameter12)) {
                bundle.putString("content", queryParameter12);
            }
            String queryParameter13 = uri.getQueryParameter("aclid");
            if (!TextUtils.isEmpty(queryParameter13)) {
                bundle.putString("aclid", queryParameter13);
            }
            String queryParameter14 = uri.getQueryParameter("cp1");
            if (!TextUtils.isEmpty(queryParameter14)) {
                bundle.putString("cp1", queryParameter14);
            }
            String queryParameter15 = uri.getQueryParameter("anid");
            if (!TextUtils.isEmpty(queryParameter15)) {
                bundle.putString("anid", queryParameter15);
            }
            if (!TextUtils.isEmpty(queryParameter6)) {
                bundle.putString("campaign_id", queryParameter6);
            }
            if (!TextUtils.isEmpty(queryParameter7)) {
                bundle.putString("dclid", queryParameter7);
            }
            String queryParameter16 = uri.getQueryParameter("utm_source_platform");
            if (!TextUtils.isEmpty(queryParameter16)) {
                bundle.putString("source_platform", queryParameter16);
            }
            String queryParameter17 = uri.getQueryParameter("utm_creative_format");
            if (!TextUtils.isEmpty(queryParameter17)) {
                bundle.putString("creative_format", queryParameter17);
            }
            String queryParameter18 = uri.getQueryParameter("utm_marketing_tactic");
            if (!TextUtils.isEmpty(queryParameter18)) {
                bundle.putString("marketing_tactic", queryParameter18);
            }
            if (!TextUtils.isEmpty(queryParameter8)) {
                bundle.putString("srsltid", queryParameter8);
            }
            if (!TextUtils.isEmpty(queryParameter9)) {
                bundle.putString(str, queryParameter9);
            }
            return bundle;
        } catch (UnsupportedOperationException e) {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.j.g("Install referrer url isn't a hierarchical URI", e);
            return null;
        }
    }

    public final SecureRandom d0() {
        S();
        if (this.d == null) {
            this.d = new SecureRandom();
        }
        return this.d;
    }

    public final Bundle d1(Bundle bundle) {
        Bundle bundle2 = new Bundle();
        if (bundle != null) {
            for (String str : bundle.keySet()) {
                Object objY = Y(bundle.get(str), str);
                if (objY == null) {
                    Y y = (Y) this.b;
                    I i = y.i;
                    Y.k(i);
                    i.l.g("Param value can't be null", y.m.e(str));
                } else {
                    m0(bundle2, str, objY);
                }
            }
        }
        return bundle2;
    }

    public final void f0(Bundle bundle, long j2) {
        long j3 = bundle.getLong("_et");
        if (j3 != 0) {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.j.g("Params already contained engagement", Long.valueOf(j3));
        } else {
            j3 = 0;
        }
        bundle.putLong("_et", j2 + j3);
    }

    public final void g0(Bundle bundle, int i, String str, Object obj) {
        if (S0(i, bundle)) {
            ((Y) this.b).getClass();
            bundle.putString("_ev", b0(str, 40, true));
            if (obj != null) {
                if ((obj instanceof String) || (obj instanceof CharSequence)) {
                    bundle.putLong("_el", obj.toString().length());
                }
            }
        }
    }

    public final void i0(Bundle bundle, Bundle bundle2) {
        if (bundle2 == null) {
            return;
        }
        for (String str : bundle2.keySet()) {
            if (!bundle.containsKey(str)) {
                x1 x1Var = ((Y) this.b).l;
                Y.h(x1Var);
                x1Var.m0(bundle, str, bundle2.get(str));
            }
        }
    }

    public final void j0(Parcelable[] parcelableArr, int i) {
        com.google.android.gms.common.internal.u.h(parcelableArr);
        for (Parcelable parcelable : parcelableArr) {
            Bundle bundle = (Bundle) parcelable;
            Iterator it2 = new TreeSet(bundle.keySet()).iterator();
            int i2 = 0;
            boolean z = false;
            while (it2.hasNext()) {
                String str = (String) it2.next();
                if (M0(str) && !x0(str, AbstractC3883n0.h) && (i2 = i2 + 1) > i) {
                    Y y = (Y) this.b;
                    if (!y.g.f0(null, AbstractC3893t.r1) || !z) {
                        I i3 = y.i;
                        Y.k(i3);
                        D d = y.m;
                        i3.i.h("Param can't contain more than " + i + " item-scoped custom parameters", d.e(str), d.b(bundle));
                    }
                    S0(28, bundle);
                    bundle.remove(str);
                    z = true;
                }
            }
        }
    }

    public final void k0(J j2, int i) {
        Bundle bundle = (Bundle) j2.e;
        Iterator it2 = new TreeSet(bundle.keySet()).iterator();
        int i2 = 0;
        boolean z = false;
        while (it2.hasNext()) {
            String str = (String) it2.next();
            if (M0(str) && (i2 = i2 + 1) > i) {
                Y y = (Y) this.b;
                if (!y.g.f0(null, AbstractC3893t.r1) || !z) {
                    String strC = AbstractC0147y.c(i, "Event can't contain more than ", " params");
                    I i3 = y.i;
                    Y.k(i3);
                    D d = y.m;
                    i3.i.h(strC, d.d((String) j2.c), d.b(bundle));
                    S0(5, bundle);
                }
                bundle.remove(str);
                z = true;
            }
        }
    }

    public final void m0(Bundle bundle, String str, Object obj) {
        if (bundle == null) {
            return;
        }
        if (obj instanceof Long) {
            bundle.putLong(str, ((Long) obj).longValue());
            return;
        }
        if (obj instanceof String) {
            bundle.putString(str, String.valueOf(obj));
            return;
        }
        if (obj instanceof Double) {
            bundle.putDouble(str, ((Double) obj).doubleValue());
            return;
        }
        if (obj instanceof Bundle[]) {
            bundle.putParcelableArray(str, (Bundle[]) obj);
            return;
        }
        if (str != null) {
            String simpleName = obj != null ? obj.getClass().getSimpleName() : null;
            Y y = (Y) this.b;
            I i = y.i;
            Y.k(i);
            i.l.h("Not putting event parameter. Invalid value type. name, type", y.m.e(str), simpleName);
        }
    }

    public final void n0(com.google.android.gms.internal.measurement.L l, boolean z) {
        Bundle bundle = new Bundle();
        bundle.putBoolean("r", z);
        try {
            l.t1(bundle);
        } catch (RemoteException e) {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.j.g("Error returning boolean value to wrapper", e);
        }
    }

    public final void o0(com.google.android.gms.internal.measurement.L l, ArrayList arrayList) {
        Bundle bundle = new Bundle();
        bundle.putParcelableArrayList("r", arrayList);
        try {
            l.t1(bundle);
        } catch (RemoteException e) {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.j.g("Error returning bundle list to wrapper", e);
        }
    }

    public final void p0(com.google.android.gms.internal.measurement.L l, Bundle bundle) {
        try {
            l.t1(bundle);
        } catch (RemoteException e) {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.j.g("Error returning bundle value to wrapper", e);
        }
    }

    public final void q0(com.google.android.gms.internal.measurement.L l, byte[] bArr) {
        Bundle bundle = new Bundle();
        bundle.putByteArray("r", bArr);
        try {
            l.t1(bundle);
        } catch (RemoteException e) {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.j.g("Error returning byte array to wrapper", e);
        }
    }

    public final void r0(com.google.android.gms.internal.measurement.L l, int i) {
        Bundle bundle = new Bundle();
        bundle.putInt("r", i);
        try {
            l.t1(bundle);
        } catch (RemoteException e) {
            I i2 = ((Y) this.b).i;
            Y.k(i2);
            i2.j.g("Error returning int value to wrapper", e);
        }
    }

    public final void s0(com.google.android.gms.internal.measurement.L l, long j2) {
        Bundle bundle = new Bundle();
        bundle.putLong("r", j2);
        try {
            l.t1(bundle);
        } catch (RemoteException e) {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.j.g("Error returning long value to wrapper", e);
        }
    }

    public final void t0(String str, com.google.android.gms.internal.measurement.L l) {
        Bundle bundle = new Bundle();
        bundle.putString("r", str);
        try {
            l.t1(bundle);
        } catch (RemoteException e) {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.j.g("Error returning string value to wrapper", e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x0095  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int u0(java.lang.String r13, java.lang.String r14, java.lang.Object r15, android.os.Bundle r16, java.util.List r17, boolean r18, boolean r19) {
        /*
            Method dump skipped, instructions count: 325
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.x1.u0(java.lang.String, java.lang.String, java.lang.Object, android.os.Bundle, java.util.List, boolean, boolean):int");
    }

    public final int v0(String str) {
        boolean zEquals = "_ldl".equals(str);
        Y y = (Y) this.b;
        if (zEquals) {
            y.getClass();
            return 2048;
        }
        if (FieldType.FOREIGN_ID_FIELD_SUFFIX.equals(str)) {
            y.getClass();
            return 256;
        }
        if ("_lgclid".equals(str)) {
            y.getClass();
            return 100;
        }
        y.getClass();
        return 36;
    }

    public final Object w0(int i, Object obj, boolean z, boolean z2) {
        if (obj == null) {
            return null;
        }
        if ((obj instanceof Long) || (obj instanceof Double)) {
            return obj;
        }
        if (obj instanceof Integer) {
            return Long.valueOf(((Integer) obj).intValue());
        }
        if (obj instanceof Byte) {
            return Long.valueOf(((Byte) obj).byteValue());
        }
        if (obj instanceof Short) {
            return Long.valueOf(((Short) obj).shortValue());
        }
        if (obj instanceof Boolean) {
            return Long.valueOf(true != ((Boolean) obj).booleanValue() ? 0L : 1L);
        }
        if (obj instanceof Float) {
            return Double.valueOf(((Float) obj).doubleValue());
        }
        if ((obj instanceof String) || (obj instanceof Character) || (obj instanceof CharSequence)) {
            return b0(obj.toString(), i, z);
        }
        if (!z2) {
            return null;
        }
        if (!(obj instanceof Bundle[]) && !(obj instanceof Parcelable[])) {
            return null;
        }
        ArrayList arrayList = new ArrayList();
        for (Parcelable parcelable : (Parcelable[]) obj) {
            if (parcelable instanceof Bundle) {
                Bundle bundleD1 = d1((Bundle) parcelable);
                if (!bundleD1.isEmpty()) {
                    arrayList.add(bundleD1);
                }
            }
        }
        return arrayList.toArray(new Bundle[arrayList.size()]);
    }

    public final void y0(String str, String str2, Bundle bundle, List list, boolean z) {
        int iW0;
        I i;
        String str3;
        int iU0;
        List list2 = list;
        if (bundle == null) {
            return;
        }
        Y y = (Y) this.b;
        x1 x1Var = ((Y) y.g.b).l;
        Y.h(x1Var);
        int i2 = true != x1Var.K0(231100000) ? 0 : 35;
        Iterator it2 = new TreeSet(bundle.keySet()).iterator();
        int i3 = 0;
        boolean z2 = false;
        while (it2.hasNext()) {
            String str4 = (String) it2.next();
            if (list2 == null || !list2.contains(str4)) {
                iW0 = !z ? W0(str4) : 0;
                if (iW0 == 0) {
                    iW0 = V0(str4);
                }
            } else {
                iW0 = 0;
            }
            if (iW0 != 0) {
                g0(bundle, iW0, str4, iW0 == 3 ? str4 : null);
                bundle.remove(str4);
            } else {
                boolean zI0 = I0(bundle.get(str4));
                I i4 = y.i;
                if (zI0) {
                    Y.k(i4);
                    i4.l.i("Nested Bundle parameters are not allowed; discarded. event name, param name, child param name", str, str2, str4);
                    iU0 = 22;
                    i = i4;
                    str3 = null;
                } else {
                    i = i4;
                    str3 = null;
                    iU0 = u0(str, str4, bundle.get(str4), bundle, list2, z, false);
                }
                if (iU0 != 0 && !"_ev".equals(str4)) {
                    g0(bundle, iU0, str4, bundle.get(str4));
                    bundle.remove(str4);
                } else if (M0(str4) && !x0(str4, AbstractC3883n0.h)) {
                    i3++;
                    boolean zK0 = K0(231100000);
                    D d = y.m;
                    if (zK0) {
                        I i5 = i;
                        if (i3 > i2) {
                            if (!y.g.f0(str3, AbstractC3893t.r1) || !z2) {
                                Y.k(i5);
                                i5.i.h("Item can't contain more than " + i2 + " item-scoped custom params", d.d(str), d.b(bundle));
                            }
                            S0(28, bundle);
                            bundle.remove(str4);
                            list2 = list;
                            z2 = true;
                        }
                    } else {
                        Y.k(i);
                        i.i.h("Item array not supported on client's version of Google Play Services (Android Only)", d.d(str), d.b(bundle));
                        S0(23, bundle);
                        bundle.remove(str4);
                    }
                }
            }
            list2 = list;
        }
    }
}
