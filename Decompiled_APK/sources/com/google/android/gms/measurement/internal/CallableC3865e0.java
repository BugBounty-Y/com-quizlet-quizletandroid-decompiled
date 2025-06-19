package com.google.android.gms.measurement.internal;

import java.util.concurrent.Callable;

/* renamed from: com.google.android.gms.measurement.internal.e0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class CallableC3865e0 implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;
    public final /* synthetic */ String d;
    public final /* synthetic */ BinderC3869g0 e;

    public /* synthetic */ CallableC3865e0(BinderC3869g0 binderC3869g0, String str, String str2, String str3, int i) {
        this.a = i;
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = binderC3869g0;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        switch (this.a) {
            case 0:
                BinderC3869g0 binderC3869g0 = this.e;
                binderC3869g0.a.j();
                C3874j c3874j = binderC3869g0.a.c;
                r1.L(c3874j);
                return c3874j.b0(this.b, this.c, this.d);
            case 1:
                BinderC3869g0 binderC3869g02 = this.e;
                binderC3869g02.a.j();
                C3874j c3874j2 = binderC3869g02.a.c;
                r1.L(c3874j2);
                return c3874j2.b0(this.b, this.c, this.d);
            case 2:
                BinderC3869g0 binderC3869g03 = this.e;
                binderC3869g03.a.j();
                C3874j c3874j3 = binderC3869g03.a.c;
                r1.L(c3874j3);
                return c3874j3.X(this.b, this.c, this.d);
            default:
                BinderC3869g0 binderC3869g04 = this.e;
                binderC3869g04.a.j();
                C3874j c3874j4 = binderC3869g04.a.c;
                r1.L(c3874j4);
                return c3874j4.X(this.b, this.c, this.d);
        }
    }
}
