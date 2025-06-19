package com.google.android.gms.measurement.internal;

import android.app.Application;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import androidx.appcompat.widget.C0122z;
import com.google.android.gms.internal.ads.C1719Ka;
import com.google.android.gms.internal.measurement.E3;
import com.google.android.gms.internal.measurement.H1;
import com.google.android.gms.internal.measurement.I1;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABTCFKeys;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.PriorityQueue;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class D0 extends AbstractC3888q {
    public C0 d;
    public InterfaceC3885o0 e;
    public final CopyOnWriteArraySet f;
    public boolean g;
    public final AtomicReference h;
    public final Object i;
    public boolean j;
    public int k;
    public C3902x0 l;
    public C3902x0 m;
    public PriorityQueue n;
    public boolean o;
    public C3881m0 p;
    public final AtomicLong q;
    public long r;
    public final P s;
    public boolean t;
    public C3902x0 u;
    public SharedPreferencesOnSharedPreferenceChangeListenerC3900w0 v;
    public C3902x0 w;
    public final com.quizlet.data.repository.school.membership.a x;

    public D0(Y y) {
        super(y);
        this.f = new CopyOnWriteArraySet();
        this.i = new Object();
        this.j = false;
        this.k = 1;
        this.t = true;
        this.x = new com.quizlet.data.repository.school.membership.a(this, 20);
        this.h = new AtomicReference();
        this.p = C3881m0.c;
        this.r = -1L;
        this.q = new AtomicLong(0L);
        this.s = new P(y);
    }

    public static void V(D0 d0, C3881m0 c3881m0, long j, boolean z) {
        d0.S();
        d0.Q();
        Y y = (Y) d0.b;
        O o = y.h;
        Y.h(o);
        C3881m0 c3881m0Z = o.Z();
        long j2 = d0.r;
        int i = c3881m0.b;
        I i2 = y.i;
        if (j <= j2 && C3881m0.l(c3881m0Z.b, i)) {
            Y.k(i2);
            i2.m.g("Dropped out-of-date consent setting, proposed settings", c3881m0);
            return;
        }
        O o2 = y.h;
        Y.h(o2);
        o2.S();
        if (!C3881m0.l(i, o2.X().getInt("consent_source", 100))) {
            Y.k(i2);
            i2.m.g("Lower precedence consent source ignored, proposed source", Integer.valueOf(i));
            return;
        }
        SharedPreferences.Editor editorEdit = o2.X().edit();
        editorEdit.putString("consent_settings", c3881m0.j());
        editorEdit.putInt("consent_source", i);
        editorEdit.apply();
        Y.k(i2);
        i2.o.g("Setting storage consent(FE)", c3881m0);
        d0.r = j;
        if (y.r().d0()) {
            Y0 y0E = Z.e(y);
            y0E.i0(new P0(y0E, 0));
        } else {
            Y0 y0E2 = Z.e(y);
            if (y0E2.c0()) {
                y0E2.i0(new U0(y0E2, y0E2.f0(false), 1));
            }
        }
        if (z) {
            y.r().X(new AtomicReference());
        }
    }

    @Override // com.google.android.gms.measurement.internal.AbstractC3888q
    public final boolean U() {
        return false;
    }

    public final void W() {
        S();
        Q();
        Y y = (Y) this.b;
        if (y.e()) {
            C3864e c3864e = y.g;
            ((Y) c3864e.b).getClass();
            Boolean boolD0 = c3864e.d0("google_analytics_deferred_deep_link_enabled");
            if (boolD0 != null && boolD0.booleanValue()) {
                I i = y.i;
                Y.k(i);
                i.n.f("Deferred Deep Link feature enabled.");
                X x = y.j;
                Y.k(x);
                x.c0(new RunnableC3898v0(this, 0));
            }
            Y0 y0E = Z.e(y);
            zzr zzrVarF0 = y0E.f0(true);
            y0E.j0();
            Y y2 = (Y) y0E.b;
            y2.g.f0(null, AbstractC3893t.l1);
            y2.o().Y(3, new byte[0]);
            y0E.i0(new U0(y0E, zzrVarF0, 0));
            this.t = false;
            O o = y.h;
            Y.h(o);
            o.S();
            String string = o.X().getString("previous_os_version", null);
            ((Y) o.b).m().U();
            String str = Build.VERSION.RELEASE;
            if (!TextUtils.isEmpty(str) && !str.equals(string)) {
                SharedPreferences.Editor editorEdit = o.X().edit();
                editorEdit.putString("previous_os_version", str);
                editorEdit.apply();
            }
            if (TextUtils.isEmpty(string)) {
                return;
            }
            y.m().U();
            if (string.equals(str)) {
                return;
            }
            Bundle bundle = new Bundle();
            bundle.putString("_po", string);
            c0("auto", "_ou", bundle);
        }
    }

    public final void X(String str, String str2, Bundle bundle) {
        Y y = (Y) this.b;
        y.n.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        com.google.android.gms.common.internal.u.e(str);
        Bundle bundle2 = new Bundle();
        bundle2.putString("name", str);
        bundle2.putLong("creation_timestamp", jCurrentTimeMillis);
        if (str2 != null) {
            bundle2.putString("expired_event_name", str2);
            bundle2.putBundle("expired_event_params", bundle);
        }
        X x = y.j;
        Y.k(x);
        x.c0(new com.google.common.util.concurrent.d(this, false, bundle2, 29));
    }

    public final void Y() {
        Y y = (Y) this.b;
        if (!(y.a.getApplicationContext() instanceof Application) || this.d == null) {
            return;
        }
        ((Application) y.a.getApplicationContext()).unregisterActivityLifecycleCallbacks(this.d);
    }

    public final void Z() {
        E3.b();
        Y y = (Y) this.b;
        if (y.g.f0(null, AbstractC3893t.W0)) {
            X x = y.j;
            Y.k(x);
            boolean zE0 = x.e0();
            I i = y.i;
            if (zE0) {
                Y.k(i);
                i.g.f("Cannot get trigger URIs from analytics worker thread");
                return;
            }
            if (com.google.android.material.shape.e.x()) {
                Y.k(i);
                i.g.f("Cannot get trigger URIs from main thread");
                return;
            }
            Q();
            Y.k(i);
            i.o.f("Getting trigger URIs (FE)");
            AtomicReference atomicReference = new AtomicReference();
            Y.k(x);
            x.X(atomicReference, 10000L, "get trigger URIs", new RunnableC3892s0(this, atomicReference, 0));
            List list = (List) atomicReference.get();
            if (list == null) {
                Y.k(i);
                i.g.f("Timed out waiting for get trigger URIs");
            } else {
                Y.k(x);
                x.c0(new com.google.common.util.concurrent.d(28, this, list));
            }
        }
    }

    public final void a0() {
        Y y;
        String str;
        h1 h1Var;
        h1 h1Var2;
        D0 d0;
        String str2;
        int i;
        int i2;
        I1 i1;
        S();
        Y y2 = (Y) this.b;
        I i3 = y2.i;
        Y.k(i3);
        i3.n.f("Handle tcf update.");
        O o = y2.h;
        Y.h(o);
        SharedPreferences sharedPreferencesW = o.W();
        HashMap map = new HashMap();
        C3891s c3891s = AbstractC3893t.j1;
        int i4 = 2;
        int i5 = 1;
        if (((Boolean) c3891s.a(null)).booleanValue()) {
            com.google.common.collect.x xVar = j1.a;
            H1 h1 = H1.IAB_TCF_PURPOSE_STORE_AND_ACCESS_INFORMATION_ON_A_DEVICE;
            i1 i1Var = i1.a;
            y = y2;
            AbstractMap.SimpleImmutableEntry simpleImmutableEntry = new AbstractMap.SimpleImmutableEntry(h1, i1Var);
            H1 h12 = H1.IAB_TCF_PURPOSE_SELECT_BASIC_ADS;
            i1 i1Var2 = i1.b;
            AbstractMap.SimpleImmutableEntry simpleImmutableEntry2 = new AbstractMap.SimpleImmutableEntry(h12, i1Var2);
            H1 h13 = H1.IAB_TCF_PURPOSE_CREATE_A_PERSONALISED_ADS_PROFILE;
            AbstractMap.SimpleImmutableEntry simpleImmutableEntry3 = new AbstractMap.SimpleImmutableEntry(h13, i1Var);
            H1 h14 = H1.IAB_TCF_PURPOSE_SELECT_PERSONALISED_ADS;
            AbstractMap.SimpleImmutableEntry simpleImmutableEntry4 = new AbstractMap.SimpleImmutableEntry(h14, i1Var);
            H1 h15 = H1.IAB_TCF_PURPOSE_MEASURE_AD_PERFORMANCE;
            List listAsList = Arrays.asList(simpleImmutableEntry, simpleImmutableEntry2, simpleImmutableEntry3, simpleImmutableEntry4, new AbstractMap.SimpleImmutableEntry(h15, i1Var2), new AbstractMap.SimpleImmutableEntry(H1.IAB_TCF_PURPOSE_APPLY_MARKET_RESEARCH_TO_GENERATE_AUDIENCE_INSIGHTS, i1Var2), new AbstractMap.SimpleImmutableEntry(H1.IAB_TCF_PURPOSE_DEVELOP_AND_IMPROVE_PRODUCTS, i1Var2));
            C0122z c0122z = new C0122z(listAsList != null ? listAsList.size() : 4);
            c0122z.v(listAsList);
            com.google.common.collect.C cH = c0122z.h();
            int i6 = com.google.common.collect.o.c;
            com.google.common.collect.E e = new com.google.common.collect.E("CH");
            char[] cArr = new char[5];
            int iA = j1.a(sharedPreferencesW, "IABTCF_CmpSdkID");
            int iA2 = j1.a(sharedPreferencesW, OTIABTCFKeys.IABTCF_POLICYVERSION);
            int iA3 = j1.a(sharedPreferencesW, "IABTCF_gdprApplies");
            int iA4 = j1.a(sharedPreferencesW, "IABTCF_PurposeOneTreatment");
            int iA5 = j1.a(sharedPreferencesW, OTIABTCFKeys.IABTCF_ADVERTISER_CONSENT_MODE);
            String strB = j1.b(sharedPreferencesW, "IABTCF_PublisherCC");
            C0122z c0122z2 = new C0122z(4);
            com.google.common.collect.A a = cH.b;
            if (a == null) {
                str2 = strB;
                i2 = iA4;
                i = iA5;
                com.google.common.collect.A a2 = new com.google.common.collect.A(cH, new com.google.common.collect.B(cH.e, 0, cH.f));
                cH.b = a2;
                a = a2;
            } else {
                str2 = strB;
                i = iA5;
                i2 = iA4;
            }
            com.google.android.gms.internal.common.g it2 = a.iterator();
            while (true) {
                boolean zHasNext = it2.hasNext();
                i1 = I1.PURPOSE_RESTRICTION_UNDEFINED;
                if (!zHasNext) {
                    break;
                }
                H1 h16 = (H1) it2.next();
                com.google.android.gms.internal.common.g gVar = it2;
                com.google.common.collect.C c = cH;
                String strB2 = j1.b(sharedPreferencesW, OTIABTCFKeys.IABTCF_PUBLISHERRESTRICTIONS + h16.a());
                if (!TextUtils.isEmpty(strB2) && strB2.length() >= 755) {
                    int iDigit = Character.digit(strB2.charAt(754), 10);
                    I1 i12 = I1.PURPOSE_RESTRICTION_NOT_ALLOWED;
                    if (iDigit < 0 || iDigit > I1.values().length || iDigit == 0) {
                        i1 = i12;
                    } else if (iDigit == i5) {
                        i1 = I1.PURPOSE_RESTRICTION_REQUIRE_CONSENT;
                    } else if (iDigit == i4) {
                        i1 = I1.PURPOSE_RESTRICTION_REQUIRE_LEGITIMATE_INTEREST;
                    }
                }
                c0122z2.u(h16, i1);
                it2 = gVar;
                cH = c;
                i4 = 2;
                i5 = 1;
            }
            com.google.common.collect.C c2 = cH;
            com.google.common.collect.C cH2 = c0122z2.h();
            String strB3 = j1.b(sharedPreferencesW, "IABTCF_PurposeConsents");
            String strB4 = j1.b(sharedPreferencesW, "IABTCF_VendorConsents");
            boolean z = !TextUtils.isEmpty(strB4) && strB4.length() >= 755 && strB4.charAt(754) == '1';
            String strB5 = j1.b(sharedPreferencesW, OTIABTCFKeys.IABTCF_PURPOSELEGITIMATEINTERESTS);
            String strB6 = j1.b(sharedPreferencesW, "IABTCF_VendorLegitimateInterests");
            boolean z2 = !TextUtils.isEmpty(strB6) && strB6.length() >= 755 && strB6.charAt(754) == '1';
            cArr[0] = '2';
            I1 i13 = (I1) cH2.get(h1);
            I1 i14 = (I1) cH2.get(h13);
            I1 i15 = (I1) cH2.get(h14);
            I1 i16 = (I1) cH2.get(h15);
            C0122z c0122z3 = new C0122z(4);
            c0122z3.u("Version", "2");
            boolean z3 = z;
            c0122z3.u("VendorConsent", true != z ? "0" : "1");
            boolean z4 = z2;
            c0122z3.u("VendorLegitimateInterest", true != z2 ? "0" : "1");
            c0122z3.u("gdprApplies", iA3 != 1 ? "0" : "1");
            int i7 = i;
            c0122z3.u("EnableAdvertiserConsentMode", i7 != 1 ? "0" : "1");
            c0122z3.u("PolicyVersion", String.valueOf(iA2));
            c0122z3.u("CmpSdkID", String.valueOf(iA));
            int i8 = i2;
            c0122z3.u("PurposeOneTreatment", i8 != 1 ? "0" : "1");
            String str3 = str2;
            c0122z3.u("PublisherCC", str3);
            c0122z3.u("PublisherRestrictions1", String.valueOf(i13 != null ? i13.a() : i1.a()));
            c0122z3.u("PublisherRestrictions3", String.valueOf(i14 != null ? i14.a() : i1.a()));
            c0122z3.u("PublisherRestrictions4", String.valueOf(i15 != null ? i15.a() : i1.a()));
            c0122z3.u("PublisherRestrictions7", String.valueOf(i16 != null ? i16.a() : i1.a()));
            c0122z3.v(com.google.common.collect.m.b("Purpose1", j1.f(h1, strB3, strB5), "Purpose3", j1.f(h13, strB3, strB5), "Purpose4", j1.f(h14, strB3, strB5), "Purpose7", j1.f(h15, strB3, strB5)).entrySet());
            c0122z3.v(com.google.common.collect.C.d(5, new Object[]{"AuthorizePurpose1", true != j1.c(h1, c2, cH2, e, cArr, i7, iA3, i8, str3, strB3, strB5, z3, z4) ? "0" : "1", "AuthorizePurpose3", true != j1.c(h13, c2, cH2, e, cArr, i7, iA3, i8, str3, strB3, strB5, z3, z4) ? "0" : "1", "AuthorizePurpose4", true != j1.c(h14, c2, cH2, e, cArr, i7, iA3, i8, str3, strB3, strB5, z3, z4) ? "0" : "1", "AuthorizePurpose7", true != j1.c(h15, c2, cH2, e, cArr, i7, iA3, i8, str3, strB3, strB5, z3, z4) ? "0" : "1", "PurposeDiagnostics", new String(cArr)}, null).entrySet());
            h1Var = new h1(c0122z3.h());
            str = "";
        } else {
            y = y2;
            String strB7 = j1.b(sharedPreferencesW, "IABTCF_VendorConsents");
            str = "";
            if (!str.equals(strB7) && strB7.length() > 754) {
                map.put("GoogleConsent", String.valueOf(strB7.charAt(754)));
            }
            int iA6 = j1.a(sharedPreferencesW, "IABTCF_gdprApplies");
            if (iA6 != -1) {
                map.put("gdprApplies", String.valueOf(iA6));
            }
            int iA7 = j1.a(sharedPreferencesW, OTIABTCFKeys.IABTCF_ADVERTISER_CONSENT_MODE);
            if (iA7 != -1) {
                map.put("EnableAdvertiserConsentMode", String.valueOf(iA7));
            }
            int iA8 = j1.a(sharedPreferencesW, OTIABTCFKeys.IABTCF_POLICYVERSION);
            if (iA8 != -1) {
                map.put("PolicyVersion", String.valueOf(iA8));
            }
            String strB8 = j1.b(sharedPreferencesW, "IABTCF_PurposeConsents");
            if (!str.equals(strB8)) {
                map.put("PurposeConsents", strB8);
            }
            int iA9 = j1.a(sharedPreferencesW, "IABTCF_CmpSdkID");
            if (iA9 != -1) {
                map.put("CmpSdkID", String.valueOf(iA9));
            }
            h1Var = new h1(map);
        }
        Y y3 = y;
        I i9 = y3.i;
        Y.k(i9);
        C1719Ka c1719Ka = i9.o;
        c1719Ka.g("Tcf preferences read", h1Var);
        boolean zF0 = y3.g.f0(null, c3891s);
        com.google.android.gms.common.util.b bVar = y3.n;
        if (!zF0) {
            if (o.c0(h1Var)) {
                Bundle bundleA = h1Var.a();
                Y.k(i9);
                c1719Ka.g("Consent generated from Tcf", bundleA);
                if (bundleA != Bundle.EMPTY) {
                    bVar.getClass();
                    i0(bundleA, -30, System.currentTimeMillis());
                }
                Bundle bundle = new Bundle();
                bundle.putString("_tcfd", h1Var.b());
                c0("auto", "_tcf", bundle);
                return;
            }
            return;
        }
        o.S();
        String string = o.X().getString("stored_tcf_param", str);
        HashMap map2 = new HashMap();
        if (TextUtils.isEmpty(string)) {
            h1Var2 = new h1(map2);
        } else {
            for (String str4 : string.split(";")) {
                String[] strArrSplit = str4.split(SimpleComparison.EQUAL_TO_OPERATION);
                if (strArrSplit.length >= 2 && j1.a.contains(strArrSplit[0])) {
                    map2.put(strArrSplit[0], strArrSplit[1]);
                }
            }
            h1Var2 = new h1(map2);
        }
        if (o.c0(h1Var)) {
            Bundle bundleA2 = h1Var.a();
            Y.k(i9);
            c1719Ka.g("Consent generated from Tcf", bundleA2);
            if (bundleA2 != Bundle.EMPTY) {
                bVar.getClass();
                d0 = this;
                d0.i0(bundleA2, -30, System.currentTimeMillis());
            } else {
                d0 = this;
            }
            Bundle bundle2 = new Bundle();
            HashMap map3 = h1Var2.a;
            String str5 = (map3.isEmpty() || ((String) map3.get("Version")) != null) ? "0" : "1";
            Bundle bundleA3 = h1Var.a();
            Bundle bundleA4 = h1Var2.a();
            bundle2.putString("_tcfm", str5.concat((bundleA3.size() == bundleA4.size() && Objects.equals(bundleA3.getString("ad_storage"), bundleA4.getString("ad_storage")) && Objects.equals(bundleA3.getString("ad_personalization"), bundleA4.getString("ad_personalization")) && Objects.equals(bundleA3.getString("ad_user_data"), bundleA4.getString("ad_user_data"))) ? "0" : "1"));
            String str6 = (String) h1Var.a.get("PurposeDiagnostics");
            if (TextUtils.isEmpty(str6)) {
                str6 = "200000";
            }
            bundle2.putString("_tcfd2", str6);
            bundle2.putString("_tcfd", h1Var.b());
            d0.c0("auto", "_tcf", bundle2);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x0059, code lost:
    
        if (r0 > 500) goto L22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0090, code lost:
    
        if (r5 > 500) goto L31;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b0(java.lang.String r15, java.lang.String r16, android.os.Bundle r17, boolean r18, boolean r19, long r20) {
        /*
            Method dump skipped, instructions count: 474
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.D0.b0(java.lang.String, java.lang.String, android.os.Bundle, boolean, boolean, long):void");
    }

    public final void c0(String str, String str2, Bundle bundle) {
        S();
        ((Y) this.b).n.getClass();
        d0(str, str2, bundle, System.currentTimeMillis());
    }

    public final void d0(String str, String str2, Bundle bundle, long j) {
        S();
        boolean z = true;
        if (this.e != null && !x1.L0(str2)) {
            z = false;
        }
        e0(str, str2, j, bundle, true, z, true);
    }

    /* JADX WARN: Removed duplicated region for block: B:189:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:79:0x019e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e0(java.lang.String r32, java.lang.String r33, long r34, android.os.Bundle r36, boolean r37, boolean r38, boolean r39) throws java.lang.IllegalAccessException, java.lang.ClassNotFoundException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            Method dump skipped, instructions count: 1224
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.D0.e0(java.lang.String, java.lang.String, long, android.os.Bundle, boolean, boolean, boolean):void");
    }

    public final void f0() {
        zzov zzovVar;
        S();
        this.o = false;
        if (r0().isEmpty() || this.j || (zzovVar = (zzov) r0().poll()) == null) {
            return;
        }
        Y y = (Y) this.b;
        x1 x1Var = y.l;
        Y.h(x1Var);
        if (x1Var.g == null) {
            x1Var.g = androidx.privacysandbox.ads.adservices.java.measurement.h.b(((Y) x1Var.b).a);
        }
        androidx.privacysandbox.ads.adservices.java.measurement.h hVar = x1Var.g;
        if (hVar != null) {
            this.j = true;
            I i = y.i;
            Y.k(i);
            C1719Ka c1719Ka = i.o;
            String str = zzovVar.a;
            c1719Ka.g("Registering trigger URI", str);
            com.google.common.util.concurrent.e eVarF = hVar.f(Uri.parse(str));
            if (eVarF != null) {
                eVarF.a(new com.google.common.util.concurrent.d(0, eVarF, new androidx.work.impl.model.c(this, false, zzovVar, 11)), new androidx.work.impl.utils.taskexecutor.b(this, 1));
            } else {
                this.j = false;
                r0().add(zzovVar);
            }
        }
    }

    public final void g0(InterfaceC3887p0 interfaceC3887p0) {
        Q();
        if (this.f.add(interfaceC3887p0)) {
            return;
        }
        I i = ((Y) this.b).i;
        Y.k(i);
        i.j.f("OnEventListener already registered");
    }

    public final void h0(Bundle bundle, long j) {
        com.google.android.gms.common.internal.u.h(bundle);
        Bundle bundle2 = new Bundle(bundle);
        boolean zIsEmpty = TextUtils.isEmpty(bundle2.getString("app_id"));
        Y y = (Y) this.b;
        if (!zIsEmpty) {
            I i = y.i;
            Y.k(i);
            i.j.f("Package name should be null when calling setConditionalUserProperty");
        }
        bundle2.remove("app_id");
        AbstractC3883n0.a(bundle2, "app_id", String.class, null);
        AbstractC3883n0.a(bundle2, "origin", String.class, null);
        AbstractC3883n0.a(bundle2, "name", String.class, null);
        AbstractC3883n0.a(bundle2, "value", Object.class, null);
        AbstractC3883n0.a(bundle2, "trigger_event_name", String.class, null);
        AbstractC3883n0.a(bundle2, "trigger_timeout", Long.class, 0L);
        AbstractC3883n0.a(bundle2, "timed_out_event_name", String.class, null);
        AbstractC3883n0.a(bundle2, "timed_out_event_params", Bundle.class, null);
        AbstractC3883n0.a(bundle2, "triggered_event_name", String.class, null);
        AbstractC3883n0.a(bundle2, "triggered_event_params", Bundle.class, null);
        AbstractC3883n0.a(bundle2, "time_to_live", Long.class, 0L);
        AbstractC3883n0.a(bundle2, "expired_event_name", String.class, null);
        AbstractC3883n0.a(bundle2, "expired_event_params", Bundle.class, null);
        com.google.android.gms.common.internal.u.e(bundle2.getString("name"));
        com.google.android.gms.common.internal.u.e(bundle2.getString("origin"));
        com.google.android.gms.common.internal.u.h(bundle2.get("value"));
        bundle2.putLong("creation_timestamp", j);
        String string = bundle2.getString("name");
        Object obj = bundle2.get("value");
        x1 x1Var = y.l;
        Y.h(x1Var);
        int iX0 = x1Var.X0(string);
        D d = y.m;
        I i2 = y.i;
        if (iX0 != 0) {
            Y.k(i2);
            i2.g.g("Invalid conditional user property name", d.f(string));
            return;
        }
        x1 x1Var2 = y.l;
        Y.h(x1Var2);
        if (x1Var2.T0(obj, string) != 0) {
            Y.k(i2);
            i2.g.h("Invalid conditional user property value", d.f(string), obj);
            return;
        }
        Object objZ = x1Var2.Z(obj, string);
        if (objZ == null) {
            Y.k(i2);
            i2.g.h("Unable to normalize conditional user property value", d.f(string), obj);
            return;
        }
        AbstractC3883n0.e(bundle2, objZ);
        long j2 = bundle2.getLong("trigger_timeout");
        if (!TextUtils.isEmpty(bundle2.getString("trigger_event_name")) && (j2 > 15552000000L || j2 < 1)) {
            Y.k(i2);
            i2.g.h("Invalid conditional user property timeout", d.f(string), Long.valueOf(j2));
            return;
        }
        long j3 = bundle2.getLong("time_to_live");
        if (j3 <= 15552000000L && j3 >= 1) {
            X x = y.j;
            Y.k(x);
            x.c0(new RunnableC3894t0(this, bundle2, 1));
        } else {
            Y.k(i2);
            i2.g.h("Invalid conditional user property time to live", d.f(string), Long.valueOf(j3));
        }
    }

    public final void i0(Bundle bundle, int i, long j) {
        Object obj;
        EnumC3875j0 enumC3875j0;
        String string;
        Q();
        C3881m0 c3881m0 = C3881m0.c;
        EnumC3879l0[] enumC3879l0Arr = EnumC3877k0.STORAGE.a;
        int length = enumC3879l0Arr.length;
        int i2 = 0;
        while (true) {
            obj = null;
            if (i2 >= length) {
                break;
            }
            String str = enumC3879l0Arr[i2].a;
            if (bundle.containsKey(str) && (string = bundle.getString(str)) != null) {
                if (string.equals("granted")) {
                    obj = Boolean.TRUE;
                } else if (string.equals("denied")) {
                    obj = Boolean.FALSE;
                }
                if (obj == null) {
                    obj = string;
                    break;
                }
            }
            i2++;
        }
        Y y = (Y) this.b;
        if (obj != null) {
            I i3 = y.i;
            Y.k(i3);
            i3.l.g("Ignoring invalid consent setting", obj);
            I i4 = y.i;
            Y.k(i4);
            i4.l.f("Valid consent values are 'granted', 'denied'");
        }
        X x = y.j;
        Y.k(x);
        boolean zE0 = x.e0();
        C3881m0 c3881m0D = C3881m0.d(i, bundle);
        Iterator it2 = c3881m0D.a.values().iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            enumC3875j0 = EnumC3875j0.UNINITIALIZED;
            if (!zHasNext) {
                break;
            } else if (((EnumC3875j0) it2.next()) != enumC3875j0) {
                m0(c3881m0D, zE0);
                break;
            }
        }
        C3878l c3878lA = C3878l.a(i, bundle);
        Iterator it3 = c3878lA.e.values().iterator();
        while (true) {
            if (!it3.hasNext()) {
                break;
            } else if (((EnumC3875j0) it3.next()) != enumC3875j0) {
                j0(c3878lA, zE0);
                break;
            }
        }
        Boolean boolD = C3878l.d(bundle);
        if (boolD != null) {
            String str2 = i == -30 ? "tcf" : "app";
            if (zE0) {
                o0(j, boolD.toString(), str2, "allow_personalized_ads");
            } else {
                n0(str2, "allow_personalized_ads", boolD.toString(), false, j);
            }
        }
    }

    public final void j0(C3878l c3878l, boolean z) {
        androidx.camera.core.impl.utils.futures.h hVar = new androidx.camera.core.impl.utils.futures.h(this, false, c3878l, 27);
        if (z) {
            S();
            hVar.run();
        } else {
            X x = ((Y) this.b).j;
            Y.k(x);
            x.c0(hVar);
        }
    }

    public final void k0(InterfaceC3885o0 interfaceC3885o0) {
        S();
        Q();
        InterfaceC3885o0 interfaceC3885o02 = this.e;
        if (interfaceC3885o0 != interfaceC3885o02) {
            com.google.android.gms.common.internal.u.j("EventInterceptor already set.", interfaceC3885o02 == null);
        }
        this.e = interfaceC3885o0;
    }

    public final void l0(C3881m0 c3881m0) {
        S();
        boolean z = (c3881m0.k(EnumC3879l0.ANALYTICS_STORAGE) && c3881m0.k(EnumC3879l0.AD_STORAGE)) || ((Y) this.b).r().c0();
        Y y = (Y) this.b;
        X x = y.j;
        Y.k(x);
        x.S();
        if (z != y.C) {
            X x2 = y.j;
            Y.k(x2);
            x2.S();
            y.C = z;
            O o = ((Y) this.b).h;
            Y.h(o);
            o.S();
            Boolean boolValueOf = o.X().contains("measurement_enabled_from_api") ? Boolean.valueOf(o.X().getBoolean("measurement_enabled_from_api", true)) : null;
            if (!z || boolValueOf == null || boolValueOf.booleanValue()) {
                p0(Boolean.valueOf(z), false);
            }
        }
    }

    /*  JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Can't find top splitter block for handler:B:70:0x0116
        	at jadx.core.utils.BlockUtils.getTopSplitterForHandler(BlockUtils.java:1178)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.collectHandlerRegions(ExcHandlersRegionMaker.java:53)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.process(ExcHandlersRegionMaker.java:38)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:27)
        */
    public final void m0(com.google.android.gms.measurement.internal.C3881m0 r14, boolean r15) {
        /*
            Method dump skipped, instructions count: 280
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.D0.m0(com.google.android.gms.measurement.internal.m0, boolean):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0021  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void n0(java.lang.String r12, java.lang.String r13, java.lang.Object r14, boolean r15, long r16) {
        /*
            Method dump skipped, instructions count: 215
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.D0.n0(java.lang.String, java.lang.String, java.lang.Object, boolean, long):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0057  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void o0(long r20, java.lang.Object r22, java.lang.String r23, java.lang.String r24) {
        /*
            Method dump skipped, instructions count: 244
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.D0.o0(long, java.lang.Object, java.lang.String, java.lang.String):void");
    }

    public final void p0(Boolean bool, boolean z) {
        S();
        Q();
        Y y = (Y) this.b;
        I i = y.i;
        Y.k(i);
        i.n.g("Setting app measurement enabled (FE)", bool);
        O o = y.h;
        Y.h(o);
        o.S();
        SharedPreferences.Editor editorEdit = o.X().edit();
        if (bool != null) {
            editorEdit.putBoolean("measurement_enabled", bool.booleanValue());
        } else {
            editorEdit.remove("measurement_enabled");
        }
        editorEdit.apply();
        if (z) {
            o.S();
            SharedPreferences.Editor editorEdit2 = o.X().edit();
            if (bool != null) {
                editorEdit2.putBoolean("measurement_enabled_from_api", bool.booleanValue());
            } else {
                editorEdit2.remove("measurement_enabled_from_api");
            }
            editorEdit2.apply();
        }
        X x = y.j;
        Y.k(x);
        x.S();
        if (y.C || !(bool == null || bool.booleanValue())) {
            q0();
        }
    }

    public final void q0() {
        S();
        Y y = (Y) this.b;
        O o = y.h;
        Y.h(o);
        String strL = o.o.l();
        if (strL != null) {
            boolean zEquals = "unset".equals(strL);
            com.google.android.gms.common.util.b bVar = y.n;
            if (zEquals) {
                bVar.getClass();
                o0(System.currentTimeMillis(), null, "app", "_npa");
            } else {
                Long lValueOf = Long.valueOf(true != "true".equals(strL) ? 0L : 1L);
                bVar.getClass();
                o0(System.currentTimeMillis(), lValueOf, "app", "_npa");
            }
        }
        boolean zA = y.a();
        I i = y.i;
        if (!zA || !this.t) {
            Y.k(i);
            i.n.f("Updating Scion state (FE)");
            Y0 y0R = y.r();
            y0R.S();
            y0R.Q();
            y0R.i0(new T0(y0R, y0R.f0(true), 2));
            return;
        }
        Y.k(i);
        i.n.f("Recording app launch after enabling measurement for the first time (FE)");
        W();
        g1 g1Var = y.k;
        Y.j(g1Var);
        g1Var.f.E();
        X x = y.j;
        Y.k(x);
        x.c0(new RunnableC3898v0(this, 2));
    }

    public final PriorityQueue r0() {
        if (this.n == null) {
            this.n = new PriorityQueue(Comparator.comparing(new C3890r0(), new androidx.constraintlayout.core.e(27)));
        }
        return this.n;
    }
}
