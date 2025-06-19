package com.google.android.gms.measurement.internal;

import android.text.TextUtils;
import android.util.Log;
import com.google.android.gms.internal.ads.C1719Ka;

/* loaded from: classes2.dex */
public final class I extends AbstractC3871h0 {
    public char d;
    public long e;
    public String f;
    public final C1719Ka g;
    public final C1719Ka h;
    public final C1719Ka i;
    public final C1719Ka j;
    public final C1719Ka k;
    public final C1719Ka l;
    public final C1719Ka m;
    public final C1719Ka n;
    public final C1719Ka o;

    public I(Y y) {
        super(y);
        this.d = (char) 0;
        this.e = -1L;
        this.g = new C1719Ka(this, 6, false, false);
        this.h = new C1719Ka(this, 6, true, false);
        this.i = new C1719Ka(this, 6, false, true);
        this.j = new C1719Ka(this, 5, false, false);
        this.k = new C1719Ka(this, 5, true, false);
        this.l = new C1719Ka(this, 5, false, true);
        this.m = new C1719Ka(this, 4, false, false);
        this.n = new C1719Ka(this, 3, false, false);
        this.o = new C1719Ka(this, 2, false, false);
    }

    public static H a0(String str) {
        if (str == null) {
            return null;
        }
        return new H(str);
    }

    public static String b0(boolean z, String str, Object obj, Object obj2, Object obj3) {
        String strC0 = c0(obj, z);
        String strC02 = c0(obj2, z);
        String strC03 = c0(obj3, z);
        StringBuilder sb = new StringBuilder();
        String str2 = "";
        if (str == null) {
            str = "";
        }
        if (!TextUtils.isEmpty(str)) {
            sb.append(str);
            str2 = ": ";
        }
        String str3 = ", ";
        if (!TextUtils.isEmpty(strC0)) {
            sb.append(str2);
            sb.append(strC0);
            str2 = ", ";
        }
        if (TextUtils.isEmpty(strC02)) {
            str3 = str2;
        } else {
            sb.append(str2);
            sb.append(strC02);
        }
        if (!TextUtils.isEmpty(strC03)) {
            sb.append(str3);
            sb.append(strC03);
        }
        return sb.toString();
    }

    public static String c0(Object obj, boolean z) {
        int iLastIndexOf;
        String className;
        int iLastIndexOf2;
        if (obj == null) {
            return "";
        }
        if (obj instanceof Integer) {
            obj = Long.valueOf(((Integer) obj).intValue());
        }
        if (obj instanceof Long) {
            if (!z) {
                return obj.toString();
            }
            Long l = (Long) obj;
            if (Math.abs(l.longValue()) < 100) {
                return obj.toString();
            }
            char cCharAt = obj.toString().charAt(0);
            String strValueOf = String.valueOf(Math.abs(l.longValue()));
            long jRound = Math.round(Math.pow(10.0d, strValueOf.length() - 1));
            long jRound2 = Math.round(Math.pow(10.0d, strValueOf.length()) - 1.0d);
            StringBuilder sb = new StringBuilder();
            String str = cCharAt == '-' ? "-" : "";
            sb.append(str);
            sb.append(jRound);
            sb.append("...");
            sb.append(str);
            sb.append(jRound2);
            return sb.toString();
        }
        if (obj instanceof Boolean) {
            return obj.toString();
        }
        if (!(obj instanceof Throwable)) {
            return obj instanceof H ? ((H) obj).a : z ? "-" : obj.toString();
        }
        Throwable th = (Throwable) obj;
        StringBuilder sb2 = new StringBuilder(z ? th.getClass().getName() : th.toString());
        String canonicalName = Y.class.getCanonicalName();
        String strSubstring = (TextUtils.isEmpty(canonicalName) || (iLastIndexOf = canonicalName.lastIndexOf(46)) == -1) ? "" : canonicalName.substring(0, iLastIndexOf);
        StackTraceElement[] stackTrace = th.getStackTrace();
        int length = stackTrace.length;
        int i = 0;
        while (true) {
            if (i >= length) {
                break;
            }
            StackTraceElement stackTraceElement = stackTrace[i];
            if (!stackTraceElement.isNativeMethod() && (className = stackTraceElement.getClassName()) != null) {
                if (((TextUtils.isEmpty(className) || (iLastIndexOf2 = className.lastIndexOf(46)) == -1) ? "" : className.substring(0, iLastIndexOf2)).equals(strSubstring)) {
                    sb2.append(": ");
                    sb2.append(stackTraceElement);
                    break;
                }
            }
            i++;
        }
        return sb2.toString();
    }

    @Override // com.google.android.gms.measurement.internal.AbstractC3871h0
    public final boolean T() {
        return false;
    }

    public final C1719Ka W() {
        return this.n;
    }

    public final C1719Ka X() {
        return this.g;
    }

    public final C1719Ka Y() {
        return this.o;
    }

    public final C1719Ka Z() {
        return this.j;
    }

    public final String d0() {
        String str;
        synchronized (this) {
            try {
                if (this.f == null) {
                    Y y = (Y) this.b;
                    String str2 = y.d;
                    if (str2 != null) {
                        this.f = str2;
                    } else {
                        ((Y) y.g.b).getClass();
                        this.f = "FA";
                    }
                }
                com.google.android.gms.common.internal.u.h(this.f);
                str = this.f;
            } catch (Throwable th) {
                throw th;
            }
        }
        return str;
    }

    public final void e0(int i, boolean z, boolean z2, String str, Object obj, Object obj2, Object obj3) {
        if (!z && Log.isLoggable(d0(), i)) {
            Log.println(i, d0(), b0(false, str, obj, obj2, obj3));
        }
        if (z2 || i < 5) {
            return;
        }
        com.google.android.gms.common.internal.u.h(str);
        X x = ((Y) this.b).j;
        if (x == null) {
            Log.println(6, d0(), "Scheduler not set. Not logging error/warn");
        } else {
            if (!x.c) {
                Log.println(6, d0(), "Scheduler not initialized. Not logging error/warn");
                return;
            }
            if (i >= 9) {
                i = 8;
            }
            x.c0(new G(this, i, str, obj, obj2, obj3));
        }
    }
}
