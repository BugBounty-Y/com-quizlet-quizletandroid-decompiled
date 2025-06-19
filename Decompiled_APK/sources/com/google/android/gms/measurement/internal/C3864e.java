package com.google.android.gms.measurement.internal;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.text.TextUtils;
import java.lang.reflect.InvocationTargetException;

/* renamed from: com.google.android.gms.measurement.internal.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3864e extends androidx.compose.animation.core.J0 {
    public Boolean c;
    public String d;
    public InterfaceC3862d e;
    public Boolean f;

    public final boolean T() {
        ((Y) this.b).getClass();
        Boolean boolD0 = d0("firebase_analytics_collection_deactivated");
        return boolD0 != null && boolD0.booleanValue();
    }

    public final boolean U(String str) {
        return "1".equals(this.e.g(str, "measurement.event_sampling_enabled"));
    }

    public final boolean V() {
        if (this.c == null) {
            Boolean boolD0 = d0("app_measurement_lite");
            this.c = boolD0;
            if (boolD0 == null) {
                this.c = Boolean.FALSE;
            }
        }
        return this.c.booleanValue() || !((Y) this.b).e;
    }

    public final String W(String str) {
        Y y = (Y) this.b;
        try {
            String str2 = (String) Class.forName("android.os.SystemProperties").getMethod("get", String.class, String.class).invoke(null, str, "");
            com.google.android.gms.common.internal.u.h(str2);
            return str2;
        } catch (ClassNotFoundException e) {
            I i = y.i;
            Y.k(i);
            i.g.g("Could not find SystemProperties class", e);
            return "";
        } catch (IllegalAccessException e2) {
            I i2 = y.i;
            Y.k(i2);
            i2.g.g("Could not access SystemProperties.get()", e2);
            return "";
        } catch (NoSuchMethodException e3) {
            I i3 = y.i;
            Y.k(i3);
            i3.g.g("Could not find SystemProperties.get() method", e3);
            return "";
        } catch (InvocationTargetException e4) {
            I i4 = y.i;
            Y.k(i4);
            i4.g.g("SystemProperties.get() threw an exception", e4);
            return "";
        }
    }

    public final double X(String str, C3891s c3891s) {
        if (TextUtils.isEmpty(str)) {
            return ((Double) c3891s.a(null)).doubleValue();
        }
        String strG = this.e.g(str, c3891s.a);
        if (TextUtils.isEmpty(strG)) {
            return ((Double) c3891s.a(null)).doubleValue();
        }
        try {
            return ((Double) c3891s.a(Double.valueOf(Double.parseDouble(strG)))).doubleValue();
        } catch (NumberFormatException unused) {
            return ((Double) c3891s.a(null)).doubleValue();
        }
    }

    public final int Y(String str, C3891s c3891s) {
        if (TextUtils.isEmpty(str)) {
            return ((Integer) c3891s.a(null)).intValue();
        }
        String strG = this.e.g(str, c3891s.a);
        if (TextUtils.isEmpty(strG)) {
            return ((Integer) c3891s.a(null)).intValue();
        }
        try {
            return ((Integer) c3891s.a(Integer.valueOf(Integer.parseInt(strG)))).intValue();
        } catch (NumberFormatException unused) {
            return ((Integer) c3891s.a(null)).intValue();
        }
    }

    public final long Z() {
        ((Y) this.b).getClass();
        return 119002L;
    }

    public final long a0(String str, C3891s c3891s) {
        if (TextUtils.isEmpty(str)) {
            return ((Long) c3891s.a(null)).longValue();
        }
        String strG = this.e.g(str, c3891s.a);
        if (TextUtils.isEmpty(strG)) {
            return ((Long) c3891s.a(null)).longValue();
        }
        try {
            return ((Long) c3891s.a(Long.valueOf(Long.parseLong(strG)))).longValue();
        } catch (NumberFormatException unused) {
            return ((Long) c3891s.a(null)).longValue();
        }
    }

    public final Bundle b0() {
        Y y = (Y) this.b;
        try {
            Context context = y.a;
            Context context2 = y.a;
            PackageManager packageManager = context.getPackageManager();
            I i = y.i;
            if (packageManager == null) {
                Y.k(i);
                i.g.f("Failed to load metadata: PackageManager is null");
                return null;
            }
            ApplicationInfo applicationInfoA = com.google.android.gms.common.wrappers.c.a(context2).a(context2.getPackageName(), 128);
            if (applicationInfoA != null) {
                return applicationInfoA.metaData;
            }
            Y.k(i);
            i.g.f("Failed to load metadata: ApplicationInfo is null");
            return null;
        } catch (PackageManager.NameNotFoundException e) {
            I i2 = y.i;
            Y.k(i2);
            i2.g.g("Failed to load metadata: Package name not found", e);
            return null;
        }
    }

    public final EnumC3875j0 c0(String str, boolean z) {
        Object obj;
        com.google.android.gms.common.internal.u.e(str);
        Bundle bundleB0 = b0();
        Y y = (Y) this.b;
        if (bundleB0 == null) {
            I i = y.i;
            Y.k(i);
            i.g.f("Failed to load metadata: Metadata bundle is null");
            obj = null;
        } else {
            obj = bundleB0.get(str);
        }
        EnumC3875j0 enumC3875j0 = EnumC3875j0.UNINITIALIZED;
        if (obj == null) {
            return enumC3875j0;
        }
        if (Boolean.TRUE.equals(obj)) {
            return EnumC3875j0.GRANTED;
        }
        if (Boolean.FALSE.equals(obj)) {
            return EnumC3875j0.DENIED;
        }
        if (z && "eu_consent_policy".equals(obj)) {
            return EnumC3875j0.POLICY;
        }
        I i2 = y.i;
        Y.k(i2);
        i2.j.g("Invalid manifest metadata for", str);
        return enumC3875j0;
    }

    public final Boolean d0(String str) {
        com.google.android.gms.common.internal.u.e(str);
        Bundle bundleB0 = b0();
        if (bundleB0 != null) {
            if (bundleB0.containsKey(str)) {
                return Boolean.valueOf(bundleB0.getBoolean(str));
            }
            return null;
        }
        I i = ((Y) this.b).i;
        Y.k(i);
        i.g.f("Failed to load metadata: Metadata bundle is null");
        return null;
    }

    public final String e0(String str, C3891s c3891s) {
        return TextUtils.isEmpty(str) ? (String) c3891s.a(null) : (String) c3891s.a(this.e.g(str, c3891s.a));
    }

    public final boolean f0(String str, C3891s c3891s) {
        if (TextUtils.isEmpty(str)) {
            return ((Boolean) c3891s.a(null)).booleanValue();
        }
        String strG = this.e.g(str, c3891s.a);
        return TextUtils.isEmpty(strG) ? ((Boolean) c3891s.a(null)).booleanValue() : ((Boolean) c3891s.a(Boolean.valueOf("1".equals(strG)))).booleanValue();
    }

    public final boolean g0() {
        Boolean boolD0 = d0("google_analytics_automatic_screen_reporting_enabled");
        return boolD0 == null || boolD0.booleanValue();
    }
}
