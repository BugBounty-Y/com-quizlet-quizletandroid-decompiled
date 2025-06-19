package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.view.View;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.g5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2083g5 extends AbstractCallableC2599s5 {
    public final /* synthetic */ int h = 1;
    public Object i;
    public final Object j;

    public C2083g5(Z4 z4, C1864b4 c1864b4, int i, Context context) {
        super(z4, "G1O+5tqulLBNCxZxcYiJSAGrazgAMWmQ49z8g8PEPhhOgnBizp9p2UWwJMiSx+ju", "xfUFYLaeYlsk7z1gy27YVxCq/UzpfsdVkNtosT4BuNc=", c1864b4, i, 31);
        this.i = null;
        this.j = context;
    }

    @Override // com.google.android.gms.internal.ads.AbstractCallableC2599s5
    public final void a() {
        switch (this.h) {
            case 0:
                View view = (View) this.j;
                if (view == null) {
                    return;
                }
                Boolean bool = (Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.J2);
                boolean zBooleanValue = bool.booleanValue();
                Object[] objArr = (Object[]) this.e.invoke(null, view, (Activity) this.i, bool);
                C1864b4 c1864b4 = this.d;
                synchronized (c1864b4) {
                    try {
                        long jLongValue = ((Long) objArr[0]).longValue();
                        c1864b4.e();
                        C2384n4.q0((C2384n4) c1864b4.b, jLongValue);
                        long jLongValue2 = ((Long) objArr[1]).longValue();
                        c1864b4.e();
                        C2384n4.s0((C2384n4) c1864b4.b, jLongValue2);
                        if (zBooleanValue) {
                            String str = (String) objArr[2];
                            c1864b4.e();
                            C2384n4.r0((C2384n4) c1864b4.b, str);
                        }
                    } finally {
                    }
                }
                return;
            default:
                C1864b4 c1864b42 = this.d;
                c1864b42.e();
                C2384n4.Y((C2384n4) c1864b42.b, -1L);
                c1864b42.e();
                C2384n4.T((C2384n4) c1864b42.b, -1L);
                Context context = (Context) this.j;
                if (context == null) {
                    context = this.a.a;
                }
                if (((List) this.i) == null) {
                    this.i = (List) this.e.invoke(null, context);
                }
                List list = (List) this.i;
                if (list == null || list.size() != 2) {
                    return;
                }
                synchronized (c1864b42) {
                    long jLongValue3 = ((Long) ((List) this.i).get(0)).longValue();
                    c1864b42.e();
                    C2384n4.Y((C2384n4) c1864b42.b, jLongValue3);
                    long jLongValue4 = ((Long) ((List) this.i).get(1)).longValue();
                    c1864b42.e();
                    C2384n4.T((C2384n4) c1864b42.b, jLongValue4);
                }
                return;
        }
    }

    public C2083g5(Z4 z4, C1864b4 c1864b4, int i, View view, Activity activity) {
        super(z4, "YX3pd3fZ/j0e82Z3yXv98nYqAI3nsN+d0YAKVHjoLLbjd+BRZ45hNatoujYNmZM/", "2IfMUy5zOuVT1ilWAqZrt9PNbHCY94WGDxwYlYOFZTM=", c1864b4, i, 62);
        this.j = view;
        this.i = activity;
    }
}
