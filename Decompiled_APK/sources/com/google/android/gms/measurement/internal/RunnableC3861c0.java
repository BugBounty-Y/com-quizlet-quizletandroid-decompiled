package com.google.android.gms.measurement.internal;

import android.os.Bundle;

/* renamed from: com.google.android.gms.measurement.internal.c0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC3861c0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ long d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    public /* synthetic */ RunnableC3861c0(Object obj, Object obj2, Object obj3, Object obj4, long j, int i) {
        this.a = i;
        this.b = obj2;
        this.c = obj3;
        this.e = obj4;
        this.d = j;
        this.f = obj;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                String str = (String) this.c;
                BinderC3869g0 binderC3869g0 = (BinderC3869g0) this.f;
                String str2 = (String) this.b;
                if (str2 != null) {
                    L0 l0 = new L0(this.d, (String) this.e, str2);
                    r1 r1Var = binderC3869g0.a;
                    r1Var.i().S();
                    String str3 = r1Var.G;
                    if (str3 != null) {
                        str3.equals(str);
                    }
                    r1Var.G = str;
                    r1Var.F = l0;
                    break;
                } else {
                    r1 r1Var2 = binderC3869g0.a;
                    r1Var2.i().S();
                    String str4 = r1Var2.G;
                    if (str4 == null || str4.equals(str)) {
                        r1Var2.G = str;
                        r1Var2.F = null;
                        break;
                    }
                }
                break;
            case 1:
                Object obj = this.e;
                ((D0) this.f).o0(this.d, obj, (String) this.b, (String) this.c);
                break;
            default:
                Bundle bundle = (Bundle) this.b;
                bundle.remove("screen_name");
                bundle.remove("screen_class");
                O0 o0 = (O0) this.f;
                x1 x1Var = ((Y) o0.b).l;
                Y.h(x1Var);
                o0.W((L0) this.c, (L0) this.e, this.d, true, x1Var.W("screen_view", bundle, null, false));
                break;
        }
    }
}
