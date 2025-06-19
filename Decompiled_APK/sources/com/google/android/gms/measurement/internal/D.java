package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.ArrayList;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class D {
    public static final AtomicReference b = new AtomicReference();
    public static final AtomicReference c = new AtomicReference();
    public static final AtomicReference d = new AtomicReference();
    public final androidx.appcompat.app.L a;

    public D(androidx.appcompat.app.L l) {
        this.a = l;
    }

    public static final String g(String str, String[] strArr, String[] strArr2, AtomicReference atomicReference) {
        String str2;
        com.google.android.gms.common.internal.u.h(atomicReference);
        com.google.android.gms.common.internal.u.b(strArr.length == strArr2.length);
        for (int i = 0; i < strArr.length; i++) {
            if (Objects.equals(str, strArr[i])) {
                synchronized (atomicReference) {
                    try {
                        String[] strArr3 = (String[]) atomicReference.get();
                        if (strArr3 == null) {
                            strArr3 = new String[strArr2.length];
                            atomicReference.set(strArr3);
                        }
                        str2 = strArr3[i];
                        if (str2 == null) {
                            str2 = strArr2[i] + "(" + strArr[i] + ")";
                            strArr3[i] = str2;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return str2;
            }
        }
        return str;
    }

    public final String a(Object[] objArr) {
        if (objArr == null) {
            return "[]";
        }
        StringBuilder sbU = androidx.compose.animation.d0.u("[");
        for (Object obj : objArr) {
            String strB = obj instanceof Bundle ? b((Bundle) obj) : String.valueOf(obj);
            if (strB != null) {
                if (sbU.length() != 1) {
                    sbU.append(", ");
                }
                sbU.append(strB);
            }
        }
        sbU.append("]");
        return sbU.toString();
    }

    public final String b(Bundle bundle) {
        if (bundle == null) {
            return null;
        }
        if (!this.a.T()) {
            return bundle.toString();
        }
        StringBuilder sbU = androidx.compose.animation.d0.u("Bundle[{");
        for (String str : bundle.keySet()) {
            if (sbU.length() != 8) {
                sbU.append(", ");
            }
            sbU.append(e(str));
            sbU.append(SimpleComparison.EQUAL_TO_OPERATION);
            Object obj = bundle.get(str);
            sbU.append(obj instanceof Bundle ? a(new Object[]{obj}) : obj instanceof Object[] ? a((Object[]) obj) : obj instanceof ArrayList ? a(((ArrayList) obj).toArray()) : String.valueOf(obj));
        }
        sbU.append("}]");
        return sbU.toString();
    }

    public final String c(zzbh zzbhVar) {
        androidx.appcompat.app.L l = this.a;
        if (!l.T()) {
            return zzbhVar.toString();
        }
        StringBuilder sb = new StringBuilder("origin=");
        sb.append(zzbhVar.c);
        sb.append(",name=");
        sb.append(d(zzbhVar.a));
        sb.append(",params=");
        zzbf zzbfVar = zzbhVar.b;
        sb.append(zzbfVar == null ? null : !l.T() ? zzbfVar.a.toString() : b(zzbfVar.a()));
        return sb.toString();
    }

    public final String d(String str) {
        if (str == null) {
            return null;
        }
        return !this.a.T() ? str : g(str, AbstractC3883n0.c, AbstractC3883n0.a, b);
    }

    public final String e(String str) {
        if (str == null) {
            return null;
        }
        return !this.a.T() ? str : g(str, AbstractC3883n0.f, AbstractC3883n0.e, c);
    }

    public final String f(String str) {
        if (str == null) {
            return null;
        }
        return !this.a.T() ? str : str.startsWith("_exp_") ? android.support.v4.media.session.a.B("experiment_id(", str, ")") : g(str, AbstractC3883n0.j, AbstractC3883n0.i, d);
    }
}
