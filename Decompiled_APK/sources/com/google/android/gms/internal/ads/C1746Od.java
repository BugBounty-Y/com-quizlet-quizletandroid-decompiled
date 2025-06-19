package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.Od, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1746Od extends androidx.compose.animation.core.J0 {
    public final InterfaceC2529qe c;
    public final AbstractC1794Wd d;
    public final String e;
    public final String[] f;

    public C1746Od(InterfaceC2529qe interfaceC2529qe, AbstractC1794Wd abstractC1794Wd, String str, String[] strArr) {
        super(5);
        this.c = interfaceC2529qe;
        this.d = abstractC1794Wd;
        this.e = str;
        this.f = strArr;
        com.google.android.gms.ads.internal.j.C.A.a.add(this);
    }

    @Override // androidx.compose.animation.core.J0
    public final void Q() {
        try {
            this.d.s(this.e, this.f);
        } finally {
            com.google.android.gms.ads.internal.util.F.l.post(new RunnableC1989e(this, 17));
        }
    }

    @Override // androidx.compose.animation.core.J0
    public final com.google.common.util.concurrent.e R() {
        return (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Z1)).booleanValue() && (this.d instanceof C1837ae)) ? AbstractC2270kd.f.d(new Q4(this, 2)) : super.R();
    }
}
