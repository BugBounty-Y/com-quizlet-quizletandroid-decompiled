package com.google.android.gms.internal.ads;

import android.view.View;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.l5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2299l5 extends AbstractCallableC2599s5 {
    public final /* synthetic */ int h = 3;
    public final Object i;

    public C2299l5(Z4 z4, C1864b4 c1864b4, int i, View view) {
        super(z4, "h7NW4UTeHoapcAfHjNS1jSIEsdu+S9XbBUhqH3zqKlRoFqG3FEF52d6iyzd+cmzU", "UQVAYGHTy6RzP6i5dxbs04Nz2BVdis2XDzzm3D3JwpQ=", c1864b4, i, 57);
        this.i = view;
    }

    @Override // com.google.android.gms.internal.ads.AbstractCallableC2599s5
    public final void a() {
        switch (this.h) {
            case 0:
                Method method = this.e;
                J j = (J) this.i;
                long[] jArr = (long[]) method.invoke(null, Long.valueOf(j.c), Long.valueOf(j.d), Long.valueOf(j.e), Long.valueOf(j.f));
                C1864b4 c1864b4 = this.d;
                synchronized (c1864b4) {
                    long j2 = jArr[0];
                    c1864b4.e();
                    C2384n4.w((C2384n4) c1864b4.b, j2);
                    long j3 = jArr[1];
                    c1864b4.e();
                    C2384n4.G0((C2384n4) c1864b4.b, j3);
                }
                return;
            case 1:
                Method method2 = this.e;
                C2881yn c2881yn = (C2881yn) this.i;
                List list = (List) c2881yn.b;
                c2881yn.b = Collections.EMPTY_LIST;
                int iIntValue = ((Integer) method2.invoke(null, list)).intValue();
                C1864b4 c1864b42 = this.d;
                synchronized (c1864b42) {
                    int iB = AbstractC1795We.b(iIntValue);
                    c1864b42.e();
                    C2384n4.h0((C2384n4) c1864b42.b, iB);
                }
                return;
            case 2:
                StackTraceElement[] stackTraceElementArr = (StackTraceElement[]) this.i;
                if (stackTraceElementArr != null) {
                    R4 r4 = new R4((String) this.e.invoke(null, stackTraceElementArr));
                    C1864b4 c1864b43 = this.d;
                    synchronized (c1864b43) {
                        try {
                            long jLongValue = r4.P.longValue();
                            c1864b43.e();
                            C2384n4.G((C2384n4) c1864b43.b, jLongValue);
                            if (((Boolean) r4.Q).booleanValue()) {
                                int i = true != ((Boolean) r4.R).booleanValue() ? 2 : 1;
                                c1864b43.e();
                                C2384n4.f0((C2384n4) c1864b43.b, i);
                            } else {
                                c1864b43.e();
                                C2384n4.f0((C2384n4) c1864b43.b, 3);
                            }
                        } finally {
                        }
                    }
                    return;
                }
                return;
            default:
                View view = (View) this.i;
                if (view != null) {
                    C2601s7 c2601s7 = AbstractC2773w7.z3;
                    com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                    Boolean bool = (Boolean) rVar.c.a(c2601s7);
                    Boolean bool2 = (Boolean) rVar.c.a(AbstractC2773w7.Wa);
                    String str = (String) this.e.invoke(null, view, this.a.a.getResources().getDisplayMetrics(), bool, bool2);
                    C1908c5 c1908c5 = new C1908c5();
                    HashMap mapC = AbstractC1972di.c(str);
                    if (mapC != null) {
                        c1908c5.O = (Long) mapC.get(0);
                        c1908c5.P = (Long) mapC.get(1);
                        c1908c5.Q = (Long) mapC.get(2);
                        c1908c5.R = (Long) mapC.get(3);
                        c1908c5.S = (Long) mapC.get(4);
                    }
                    C2298l4 c2298l4W = C2341m4.w();
                    long jLongValue2 = c1908c5.O.longValue();
                    c2298l4W.e();
                    C2341m4.y((C2341m4) c2298l4W.b, jLongValue2);
                    long jLongValue3 = c1908c5.P.longValue();
                    c2298l4W.e();
                    C2341m4.A((C2341m4) c2298l4W.b, jLongValue3);
                    long jLongValue4 = c1908c5.Q.longValue();
                    c2298l4W.e();
                    C2341m4.B((C2341m4) c2298l4W.b, jLongValue4);
                    if (bool2.booleanValue()) {
                        long jLongValue5 = c1908c5.S.longValue();
                        c2298l4W.e();
                        C2341m4.z((C2341m4) c2298l4W.b, jLongValue5);
                    }
                    if (bool.booleanValue()) {
                        long jLongValue6 = c1908c5.R.longValue();
                        c2298l4W.e();
                        C2341m4.x((C2341m4) c2298l4W.b, jLongValue6);
                    }
                    C2341m4 c2341m4 = (C2341m4) c2298l4W.c();
                    C1864b4 c1864b44 = this.d;
                    c1864b44.e();
                    C2384n4.a0((C2384n4) c1864b44.b, c2341m4);
                    return;
                }
                return;
        }
    }

    public C2299l5(Z4 z4, C1864b4 c1864b4, int i, J j) {
        super(z4, "L3kNtlg7QY6D9Xl7pPswVVS/MCBOYXcB4vflYd8GjH187tfdUwj4wLKq5xN70kha", "7KShiw4CrXn9e1sAZ1bf68KLoTIikFllvC3ALPO42ag=", c1864b4, i, 85);
        this.i = j;
    }

    public C2299l5(Z4 z4, C1864b4 c1864b4, int i, C2881yn c2881yn) {
        super(z4, "LLos9e8Ql/sv7oIXEM/FCVf2w4qxksYVSJjnFOiKAZfJ/fOB+3TAGyZw1OkiJRsU", "lmzfMnrRinUoapvwdylnImZxEAh1S0BzbHZ4/bdyts0=", c1864b4, i, 94);
        this.i = c2881yn;
    }

    public C2299l5(Z4 z4, C1864b4 c1864b4, int i, StackTraceElement[] stackTraceElementArr) {
        super(z4, "UtW7g7feJqOHsjIRMP7TbkL8M4VYsmVrsaULCIKJGwvBOELKcxTQZfT6AHg6wl4V", "3s4OpKjyDjUzqtut1o8wCVCKFRdtRePXWRu+sqk/xG8=", c1864b4, i, 45);
        this.i = stackTraceElementArr;
    }
}
