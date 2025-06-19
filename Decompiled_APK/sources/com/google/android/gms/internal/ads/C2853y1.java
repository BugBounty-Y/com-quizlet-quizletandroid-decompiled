package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.text.TextUtils;
import com.comscore.streaming.EventType;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.y1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2853y1 implements InterfaceC2544qt {
    public final /* synthetic */ int a;

    public /* synthetic */ C2853y1(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
    public final Object apply(Object obj) {
        int i = 1;
        int i2 = 4;
        switch (this.a) {
            case 0:
                return (I1) obj;
            case 1:
                return (I1) obj;
            case 2:
                Throwable th = (Throwable) obj;
                C2175i9 c2175i9 = AbstractC2346m9.a;
                if (((Boolean) V7.i.o()).booleanValue()) {
                    com.google.android.gms.ads.internal.j.C.h.h("prepareClickUrl.attestation1", th);
                }
                return "failure_click_attok";
            case 3:
                List list = C1673Cc.l;
                return null;
            case 4:
                return "failure_click_attok";
            case 5:
                return new C2531qg((List) obj);
            case 6:
                return new C2531qg((AbstractC2359mg) obj);
            case 7:
                ArrayList arrayList = new ArrayList();
                for (BinderC2474p8 binderC2474p8 : (List) obj) {
                    if (binderC2474p8 != null) {
                        arrayList.add(binderC2474p8);
                    }
                }
                return arrayList;
            case 8:
                ArrayList arrayList2 = new ArrayList();
                for (Jj jj : (List) obj) {
                    if (jj != null) {
                        arrayList2.add(jj);
                    }
                }
                return arrayList2;
            case 9:
                return Collections.singletonList(AbstractC2025es.E((Ui) obj));
            case 10:
                ArrayList arrayList3 = (ArrayList) obj;
                return new C2109go(i, true != arrayList3.isEmpty() ? arrayList3 : null);
            case 11:
                com.google.android.gms.appset.b bVar = (com.google.android.gms.appset.b) obj;
                return new C2453oo(bVar.a, bVar.b, 0);
            case 12:
                return new C1934co((String) obj, i2);
            case 13:
                return new C2196io((Bundle) obj, 4);
            case 14:
                return new C1934co((String) obj, 5);
            case 15:
                return null;
            case 16:
                return (Ap) obj;
            case 17:
                String str = ((C1893bq) obj).a;
                return TextUtils.isEmpty(str) ? "" : com.google.android.gms.ads.internal.util.client.f.c() ? "fakeForAdDebugLog" : str;
            case 18:
                String str2 = ((C1893bq) obj).b;
                return TextUtils.isEmpty(str2) ? "" : com.google.android.gms.ads.internal.util.client.f.c() ? "fakeForAdDebugLog" : str2;
            case 19:
                return new WD((C1847ao) obj);
            case 20:
                U u = (U) obj;
                u.getClass();
                return u.getClass().getSimpleName();
            case 21:
                return AbstractC2330lu.n(AbstractC1981ds.n(((InterfaceC2005eF) obj).h().b, new C2853y1(23)));
            case EventType.WINDOW_STATE /* 22 */:
                C2379n c2379n = (C2379n) obj;
                int i3 = C1832aG.L;
                StringBuilder sbX = android.support.v4.media.session.a.x(c2379n.a, ": ");
                sbX.append(c2379n.b);
                return sbX.toString();
            default:
                HF hf = HF.d;
                return Integer.valueOf(((J9) obj).c);
        }
    }
}
