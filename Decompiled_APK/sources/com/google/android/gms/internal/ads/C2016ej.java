package com.google.android.gms.internal.ads;

import com.comscore.streaming.EventType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.UUID;

/* renamed from: com.google.android.gms.internal.ads.ej, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2016ej implements CC {
    public final /* synthetic */ int a;

    public /* synthetic */ C2016ej(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return null;
            case 1:
                return new Mn();
            case 2:
                return null;
            case 3:
                return null;
            case 4:
                return null;
            case 5:
                return new C1974dk();
            case 6:
                return new C2535qk();
            case 7:
                return new C2620sk();
            case 8:
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new C2749vk(c2227jd);
            case 9:
                return new C2878yk(11, 12, 1007);
            case 10:
                return new C2878yk(19, 20, 1008);
            case 11:
                return new C2878yk(13, 14, 1004);
            case 12:
                return new C2878yk(1001, 1002, 1003);
            case 13:
                return new C2878yk(15, 16, 1005);
            case 14:
                return new C2878yk(17, 18, 1006);
            case 15:
                return new Ik(Jq.SIGNALS, "ttc");
            case 16:
                return new Ik(Jq.PRELOADED_LOADER, "t_load_as");
            case 17:
                return new C1975dl();
            case 18:
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                String string = UUID.randomUUID().toString();
                AbstractC1981ds.s(string);
                return string;
            case 19:
                return new C1889bm();
            case 20:
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                return new Cn(c2227jd2);
            case 21:
                return new Nn();
            case EventType.WINDOW_STATE /* 22 */:
                return new C2238jo();
            case EventType.AUDIO /* 23 */:
                C2227jd c2227jd3 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd3);
                return new C2839xo(c2227jd3, 0);
            case EventType.VIDEO /* 24 */:
                Object arrayList = new ArrayList();
                C2601s7 c2601s7 = AbstractC2773w7.Kb;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                if (!((String) rVar.c.a(c2601s7)).isEmpty()) {
                    arrayList = Arrays.asList(((String) rVar.c.a(c2601s7)).split(","));
                }
                AbstractC1981ds.s(arrayList);
                return arrayList;
            case EventType.SUBS /* 25 */:
                C2227jd c2227jd4 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd4);
                return new C2839xo(c2227jd4, 1);
            case EventType.CDN /* 26 */:
                C2227jd c2227jd5 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd5);
                return new C2839xo(c2227jd5, 2);
            case 27:
                C2227jd c2227jd6 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd6);
                return new C2839xo(c2227jd6, 4);
            case 28:
                return new C1936cq();
            default:
                return new C1893bq();
        }
    }
}
