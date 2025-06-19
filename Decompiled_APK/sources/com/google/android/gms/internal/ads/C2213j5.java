package com.google.android.gms.internal.ads;

import android.provider.Settings;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.j5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2213j5 extends AbstractCallableC2599s5 {
    public static volatile Long i;
    public static volatile Long k;
    public static volatile String m;
    public static volatile Long o;
    public final /* synthetic */ int h;
    public static final Object j = new Object();
    public static final Object l = new Object();
    public static final Object n = new Object();
    public static final Object p = new Object();

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C2213j5(Z4 z4, String str, String str2, C1864b4 c1864b4, int i2, int i3) {
        super(z4, str, str2, c1864b4, i2, i3);
        this.h = 7;
    }

    private final void b() {
        C1864b4 c1864b4 = this.d;
        c1864b4.e();
        C2384n4.A0((C2384n4) c1864b4.b, -1L);
        c1864b4.e();
        C2384n4.z0((C2384n4) c1864b4.b, -1L);
        int[] iArr = (int[]) this.e.invoke(null, this.a.a);
        synchronized (c1864b4) {
            long j2 = iArr[0];
            c1864b4.e();
            C2384n4.A0((C2384n4) c1864b4.b, j2);
            long j3 = iArr[1];
            c1864b4.e();
            C2384n4.z0((C2384n4) c1864b4.b, j3);
            int i2 = iArr[2];
            if (i2 != Integer.MIN_VALUE) {
                c1864b4.e();
                C2384n4.y0((C2384n4) c1864b4.b, i2);
            }
        }
    }

    private final void c() {
        if (k == null) {
            synchronized (l) {
                try {
                    if (k == null) {
                        k = (Long) this.e.invoke(null, null);
                    }
                } finally {
                }
            }
        }
        C1864b4 c1864b4 = this.d;
        synchronized (c1864b4) {
            long jLongValue = k.longValue();
            c1864b4.e();
            C2384n4.z((C2384n4) c1864b4.b, jLongValue);
        }
    }

    private final void d() {
        C1864b4 c1864b4 = this.d;
        c1864b4.e();
        C2384n4.C((C2384n4) c1864b4.b, "E");
        if (m == null) {
            synchronized (n) {
                try {
                    if (m == null) {
                        m = (String) this.e.invoke(null, null);
                    }
                } finally {
                }
            }
        }
        C1864b4 c1864b42 = this.d;
        synchronized (c1864b42) {
            String str = m;
            c1864b42.e();
            C2384n4.C((C2384n4) c1864b42.b, str);
        }
    }

    private final void e() {
        Boolean bool = (Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.W2);
        bool.getClass();
        String str = (String) this.e.invoke(null, this.a.a, bool);
        T4 t4 = new T4();
        t4.O = -1L;
        t4.P = -1L;
        HashMap mapC = AbstractC1972di.c(str);
        if (mapC != null) {
            t4.O = ((Long) mapC.get(0)).longValue();
            t4.P = ((Long) mapC.get(1)).longValue();
        }
        C1864b4 c1864b4 = this.d;
        synchronized (c1864b4) {
            long j2 = t4.O;
            c1864b4.e();
            C2384n4.x0((C2384n4) c1864b4.b, j2);
            long j3 = t4.P;
            c1864b4.e();
            C2384n4.D((C2384n4) c1864b4.b, j3);
        }
    }

    private final void f() {
        C1864b4 c1864b4 = this.d;
        synchronized (c1864b4) {
            String str = (String) this.e.invoke(null, null);
            W4 w4 = new W4();
            HashMap mapC = AbstractC1972di.c(str);
            if (mapC != null) {
                w4.O = (Long) mapC.get(0);
                w4.P = (Long) mapC.get(1);
            }
            long jLongValue = w4.O.longValue();
            c1864b4.e();
            C2384n4.D0((C2384n4) c1864b4.b, jLongValue);
            long jLongValue2 = w4.P.longValue();
            c1864b4.e();
            C2384n4.E0((C2384n4) c1864b4.b, jLongValue2);
        }
    }

    private final void g() {
        if (o == null) {
            synchronized (p) {
                try {
                    if (o == null) {
                        o = (Long) this.e.invoke(null, null);
                    }
                } finally {
                }
            }
        }
        C1864b4 c1864b4 = this.d;
        synchronized (c1864b4) {
            long jLongValue = o.longValue();
            c1864b4.e();
            C2384n4.X((C2384n4) c1864b4.b, jLongValue);
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractCallableC2599s5
    public final void a() throws InvocationTargetException {
        switch (this.h) {
            case 0:
                if (i == null) {
                    synchronized (j) {
                        try {
                            if (i == null) {
                                i = (Long) this.e.invoke(null, null);
                            }
                        } finally {
                        }
                    }
                }
                C1864b4 c1864b4 = this.d;
                synchronized (c1864b4) {
                    long jLongValue = i.longValue();
                    c1864b4.e();
                    C2384n4.C0((C2384n4) c1864b4.b, jLongValue);
                }
                return;
            case 1:
                c();
                return;
            case 2:
                d();
                return;
            case 3:
                g();
                return;
            case 4:
                String str = (String) this.e.invoke(null, null);
                C1864b4 c1864b42 = this.d;
                synchronized (c1864b42) {
                    c1864b42.e();
                    C2384n4.u0((C2384n4) c1864b42.b, str);
                }
                return;
            case 5:
                C1864b4 c1864b43 = this.d;
                c1864b43.e();
                C2384n4.e0((C2384n4) c1864b43.b, 3);
                try {
                    int i2 = 1;
                    if (true == ((Boolean) this.e.invoke(null, this.a.a)).booleanValue()) {
                        i2 = 2;
                    }
                    c1864b43.e();
                    C2384n4.e0((C2384n4) c1864b43.b, i2);
                    return;
                } catch (InvocationTargetException e) {
                    if (!(e.getTargetException() instanceof Settings.SettingNotFoundException)) {
                        throw e;
                    }
                    return;
                }
            case 6:
                b();
                return;
            case 7:
                int i3 = true == ((Boolean) this.e.invoke(null, this.a.a)).booleanValue() ? 2 : 1;
                C1864b4 c1864b44 = this.d;
                c1864b44.e();
                C2384n4.g0((C2384n4) c1864b44.b, i3);
                return;
            case 8:
                C1864b4 c1864b45 = this.d;
                c1864b45.e();
                C2384n4.B((C2384n4) c1864b45.b, -1L);
                long jLongValue2 = ((Long) this.e.invoke(null, this.a.a)).longValue();
                c1864b45.e();
                C2384n4.B((C2384n4) c1864b45.b, jLongValue2);
                return;
            case 9:
                e();
                return;
            case 10:
                C1864b4 c1864b46 = this.d;
                try {
                    int i4 = 1;
                    if (true == ((Boolean) this.e.invoke(null, this.a.a)).booleanValue()) {
                        i4 = 2;
                    }
                    c1864b46.e();
                    C2384n4.i0((C2384n4) c1864b46.b, i4);
                    return;
                } catch (InvocationTargetException unused) {
                    c1864b46.e();
                    C2384n4.i0((C2384n4) c1864b46.b, 3);
                    return;
                }
            case 11:
                f();
                return;
            default:
                C1864b4 c1864b47 = this.d;
                c1864b47.e();
                C2384n4.j0((C2384n4) c1864b47.b, 3);
                boolean zBooleanValue = ((Boolean) this.e.invoke(null, this.a.a)).booleanValue();
                synchronized (c1864b47) {
                    if (zBooleanValue) {
                        c1864b47.e();
                        C2384n4.j0((C2384n4) c1864b47.b, 2);
                    } else {
                        c1864b47.e();
                        C2384n4.j0((C2384n4) c1864b47.b, 1);
                    }
                }
                return;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2213j5(Z4 z4, C1864b4 c1864b4, int i2, int i3) {
        super(z4, "n8+dbEkb8sSSkj8RrAZPAIBpRkB5kUln+00UVnn84X80gYgRIiK8WSxHPJEqxXHc", "yKnJQpgvAxtK/oRpf77IDthT8ZJJ6VXKsBNJ0lMvjYQ=", c1864b4, i2, 44);
        this.h = i3;
        switch (i3) {
            case 1:
                super(z4, "2yqQbpMMcqKX38M442dN+dCyzykwnAxluzbiBDnzfSZwwykVdh1BxKbQaA6qVZBU", "1XIQFsxUhHfLRHhylour2btyczZCL08SFkmijCbkayQ=", c1864b4, i2, 22);
                break;
            case 2:
                super(z4, "d4PN2fwB2P9jxIUN6NPwGCD1vcjTZd510+VTbYWnWivlqPuX4Pd9jb/zoaClHGV2", "B7r3opNSMuM8FMoC6aVwUNpehxdhrcT61rhsqayMJbM=", c1864b4, i2, 1);
                break;
            case 3:
                super(z4, "AkswGwusnlvibekdTn6rp1TLruqBIpT26qUqw6ERX2GI+0q3NNodYWGNobvk/KA0", "+ySS/EYovSzthax5b5cNVBSw7OeHS3QqC5FfLg20T6g=", c1864b4, i2, 33);
                break;
            case 4:
                super(z4, "G6tpJfcfsXNaUQhDJn9Qju0vku5y/oa1fF8zdhZ2CFQQ0yJpdIBybAnW8Cnq7FGe", "fIK5mOsPYa+LmT3H4ctpyCeP1IjF5A1bfJROt5z4ppI=", c1864b4, i2, 89);
                break;
            case 5:
                super(z4, "WQkp0526ddrUi1BRkagos9QKSJQ1uugrJcxnlXdGVtysNEwcyhf7H4AuLi1Daa/J", "bIxRlixcWzGpKi+RzORPGFA/CCK1ebxNEgd5yxb9Upc=", c1864b4, i2, 49);
                break;
            case 6:
                super(z4, "ptULCqFpkxWHwh0HVZoMpk0Xr91rKWbEROvrSrbrHF8bfcD+J1G9qxssmqT2HcO0", "gABvx04l+Prrr7UIzRlxJTdbXEyGkYLmeTdDcw+INuA=", c1864b4, i2, 5);
                break;
            case 7:
            default:
                break;
            case 8:
                super(z4, "8IJIsIBlDz5+1RGl+6kTNxKhKd20laJu7Ry/q2vMjbAxuJnkIuDVJXV0JiVYkZ0x", "TGJcgVVlBzpT0hARXkl1Qb1oxDrm3oU5utV1aupQqoE=", c1864b4, i2, 12);
                break;
            case 9:
                super(z4, "+T/U1hw7+KZ4U7a2mmAOu7BJ15632T6q77fmzX/Xgjcy3uK841Ng+VsVpINIYuXP", "GzjxqsxzxT+aATwD+mE+LGwR24OtaI/aqws6qGNlH18=", c1864b4, i2, 3);
                break;
            case 10:
                super(z4, "4HRSTLOwWZkuNJXWodn1qJJgWaIIvv19EC2kc5Tc35PPh8H51LV3J7XsfwYf6N8B", "x59qZ2C8s/H9o8A43vx+gBO6K2fFzzXR0hkzA9nrVNs=", c1864b4, i2, 73);
                break;
            case 11:
                super(z4, "ZfusKpZJ8SBLRBp0x6BWNud7pIzhvWIkVd0V0uxTu84aE2cfWFwKn+FMoh4smXgk", "VN0WZ1yYObu9EYHkfC3f48JbFLjOwnUEkH1X8nPNLSU=", c1864b4, i2, 51);
                break;
            case 12:
                super(z4, "1BnW1+pN8ACAA5SCwHeu4aDyUa+GdAsZQaTQjOE/fWA7hyCouT0ju5bDmhkUNXUI", "kp4jwXczzGPw0lGC8OB8RleYASbnnNEZzgNaMBT0Bfw=", c1864b4, i2, 48);
                break;
        }
    }
}
