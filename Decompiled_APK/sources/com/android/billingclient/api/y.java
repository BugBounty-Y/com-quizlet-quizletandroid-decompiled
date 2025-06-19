package com.android.billingclient.api;

import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.internal.play_billing.J1;
import com.google.android.gms.internal.play_billing.K1;
import com.google.android.gms.internal.play_billing.L1;
import com.google.android.gms.internal.play_billing.M1;
import com.google.android.gms.internal.play_billing.N1;
import com.google.android.gms.internal.play_billing.O1;

/* loaded from: classes.dex */
public abstract /* synthetic */ class y {
    public static final /* synthetic */ int a = 0;

    static {
        int i = z.L0;
    }

    public static String a(Exception exc) {
        if (exc == null) {
            return null;
        }
        try {
            String simpleName = exc.getClass().getSimpleName();
            String message = exc.getMessage();
            if (message == null) {
                message = "";
            }
            String str = simpleName + ":" + message;
            int i = AbstractC3819n0.a;
            return str.length() > 40 ? str.substring(0, 40) : str;
        } catch (Throwable th) {
            AbstractC3819n0.g("BillingLogger", "Unable to get truncated exception info", th);
            return null;
        }
    }

    public static K1 b(int i, int i2, e eVar) {
        try {
            J1 j1R = K1.r();
            N1 n1R = O1.r();
            n1R.f(eVar.a);
            String str = eVar.b;
            n1R.e();
            O1.o((O1) n1R.b, str);
            n1R.g(i);
            j1R.f(n1R);
            j1R.g(i2);
            return (K1) j1R.c();
        } catch (Exception e) {
            AbstractC3819n0.g("BillingLogger", "Unable to create logging payload", e);
            return null;
        }
    }

    public static K1 c(int i, int i2, e eVar, String str) {
        try {
            N1 n1R = O1.r();
            n1R.f(eVar.a);
            String str2 = eVar.b;
            n1R.e();
            O1.o((O1) n1R.b, str2);
            n1R.g(i);
            if (str != null) {
                n1R.e();
                O1.n((O1) n1R.b, str);
            }
            J1 j1R = K1.r();
            j1R.f(n1R);
            j1R.g(i2);
            return (K1) j1R.c();
        } catch (Throwable th) {
            AbstractC3819n0.g("BillingLogger", "Unable to create logging payload", th);
            return null;
        }
    }

    public static M1 d(int i) {
        try {
            L1 l1Q = M1.q();
            l1Q.e();
            M1.p((M1) l1Q.b, i);
            return (M1) l1Q.c();
        } catch (Exception e) {
            AbstractC3819n0.g("BillingLogger", "Unable to create logging payload", e);
            return null;
        }
    }
}
