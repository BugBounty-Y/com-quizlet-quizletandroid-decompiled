package com.google.android.gms.ads.nonagon.signalgeneration;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.BC;
import com.google.android.gms.internal.ads.C1741Ne;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.CC;
import com.google.android.gms.internal.ads.HC;
import com.google.android.gms.internal.ads.Kk;

/* loaded from: classes2.dex */
public final class w implements CC {
    public final /* synthetic */ int a;
    public final C1741Ne b;
    public final HC c;

    public /* synthetic */ w(C1741Ne c1741Ne, HC hc, int i) {
        this.a = i;
        this.b = c1741Ne;
        this.c = hc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        HC hc = this.c;
        C1741Ne c1741Ne = this.b;
        switch (this.a) {
            case 0:
                Context contextA = c1741Ne.a();
                C2601s7 c2601s7 = AbstractC2773w7.a;
                return new v(contextA, com.google.android.gms.ads.internal.client.r.d.a.h(), ((C1741Ne) hc).b());
            case 1:
                return new com.quizlet.data.repository.classfolder.e((Context) c1741Ne.zzb(), (VersionInfoParcel) ((C1741Ne) hc).zzb());
            default:
                Context contextA2 = c1741Ne.a();
                Kk kk = (Kk) ((BC) hc).zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new A(contextA2, kk, c2227jd);
        }
    }
}
