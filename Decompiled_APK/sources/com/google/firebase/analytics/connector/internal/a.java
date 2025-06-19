package com.google.firebase.analytics.connector.internal;

import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_barcode.C3268u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3531s4;
import com.google.android.gms.measurement.internal.AbstractC3883n0;
import com.google.common.collect.C3922e;
import com.google.common.collect.j;
import com.google.common.collect.o;
import com.google.common.collect.x;

/* loaded from: classes2.dex */
public abstract class a {
    public static final o a;
    public static final x b;
    public static final x c;
    public static final x d;
    public static final x e;
    public static final x f;

    static {
        int i = o.c;
        Object[] objArr = new Object[15];
        objArr[0] = "_in";
        objArr[1] = "_xa";
        objArr[2] = "_xu";
        objArr[3] = "_aq";
        objArr[4] = "_aa";
        objArr[5] = "_ai";
        System.arraycopy(new String[]{"_ac", "campaign_details", "_ug", "_iapx", "_exp_set", "_exp_clear", "_exp_activate", "_exp_timeout", "_exp_expire"}, 0, objArr, 6, 9);
        a = o.m(15, objArr);
        C3922e c3922e = j.b;
        Object[] objArr2 = {"_e", "_f", "_iap", "_s", "_au", "_ui", "_cd"};
        AbstractC3531s4.e(7, objArr2);
        b = j.k(7, objArr2);
        Object[] objArr3 = {"auto", "app", "am"};
        AbstractC3531s4.e(3, objArr3);
        c = j.k(3, objArr3);
        Object[] objArr4 = {"_r", "_dbg"};
        AbstractC3531s4.e(2, objArr4);
        d = j.k(2, objArr4);
        C3268u c3268u = new C3268u(2);
        c3268u.b(AbstractC3883n0.i);
        c3268u.b(AbstractC3883n0.j);
        c3268u.c = true;
        e = j.k(c3268u.b, c3268u.a);
        Object[] objArr5 = {"^_ltv_[A-Z]{3}$", "^_cc[1-5]{1}$"};
        AbstractC3531s4.e(2, objArr5);
        f = j.k(2, objArr5);
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0074  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean a(java.lang.String r5, java.lang.String r6, android.os.Bundle r7) {
        /*
            java.lang.String r0 = "_cmp"
            boolean r6 = r0.equals(r6)
            r0 = 1
            if (r6 != 0) goto La
            return r0
        La:
            boolean r6 = c(r5)
            r1 = 0
            if (r6 != 0) goto L12
            goto L67
        L12:
            if (r7 != 0) goto L15
            goto L67
        L15:
            com.google.common.collect.x r6 = com.google.firebase.analytics.connector.internal.a.d
            int r2 = r6.d
            r3 = r1
        L1a:
            if (r3 >= r2) goto L2b
            java.lang.Object r4 = r6.get(r3)
            java.lang.String r4 = (java.lang.String) r4
            boolean r4 = r7.containsKey(r4)
            int r3 = r3 + 1
            if (r4 == 0) goto L1a
            goto L67
        L2b:
            int r6 = r5.hashCode()
            r2 = 101200(0x18b50, float:1.41811E-40)
            r3 = 2
            if (r6 == r2) goto L54
            r2 = 101230(0x18b6e, float:1.41853E-40)
            if (r6 == r2) goto L4a
            r2 = 3142703(0x2ff42f, float:4.403865E-39)
            if (r6 == r2) goto L40
            goto L5e
        L40:
            java.lang.String r6 = "fiam"
            boolean r5 = r5.equals(r6)
            if (r5 == 0) goto L5e
            r5 = r3
            goto L5f
        L4a:
            java.lang.String r6 = "fdl"
            boolean r5 = r5.equals(r6)
            if (r5 == 0) goto L5e
            r5 = r0
            goto L5f
        L54:
            java.lang.String r6 = "fcm"
            boolean r5 = r5.equals(r6)
            if (r5 == 0) goto L5e
            r5 = r1
            goto L5f
        L5e:
            r5 = -1
        L5f:
            java.lang.String r6 = "_cis"
            if (r5 == 0) goto L74
            if (r5 == r0) goto L6e
            if (r5 == r3) goto L68
        L67:
            return r1
        L68:
            java.lang.String r5 = "fiam_integration"
            r7.putString(r6, r5)
            return r0
        L6e:
            java.lang.String r5 = "fdl_integration"
            r7.putString(r6, r5)
            return r0
        L74:
            java.lang.String r5 = "fcm_integration"
            r7.putString(r6, r5)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.analytics.connector.internal.a.a(java.lang.String, java.lang.String, android.os.Bundle):boolean");
    }

    public static boolean b(Bundle bundle, String str) {
        if (!b.contains(str)) {
            if (bundle == null) {
                return true;
            }
            x xVar = d;
            int i = xVar.d;
            int i2 = 0;
            while (i2 < i) {
                boolean zContainsKey = bundle.containsKey((String) xVar.get(i2));
                i2++;
                if (zContainsKey) {
                }
            }
            return true;
        }
        return false;
    }

    public static boolean c(String str) {
        return !c.contains(str);
    }

    public static boolean d(String str, String str2) {
        if ("_ce1".equals(str2) || "_ce2".equals(str2)) {
            if (str.equals("fcm") || str.equals("frc")) {
                return true;
            }
        } else if ("_ln".equals(str2)) {
            if (str.equals("fcm") || str.equals("fiam")) {
                return true;
            }
        } else if (!e.contains(str2)) {
            x xVar = f;
            int i = xVar.d;
            int i2 = 0;
            while (i2 < i) {
                boolean zMatches = str2.matches((String) xVar.get(i2));
                i2++;
                if (zMatches) {
                }
            }
            return true;
        }
        return false;
    }
}
