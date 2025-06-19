package com.google.android.gms.internal.ads;

import android.content.Intent;
import android.net.Uri;
import com.amazon.device.ads.DTBAdSize;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.C1614q;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Set;

/* loaded from: classes2.dex */
public final class H5 implements CC {
    public final /* synthetic */ int a;

    public /* synthetic */ H5(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new G5();
            case 1:
                return com.google.android.gms.ads.internal.j.C.h;
            case 2:
                Intent intent = new Intent("android.intent.action.VIEW");
                intent.setPackage("com.android.vending");
                intent.setData(Uri.parse("https://play.google.com/d"));
                return intent;
            case 3:
                String str = C1614q.f.c;
                AbstractC1981ds.s(str);
                return str;
            case 4:
                return new ArrayDeque();
            case 5:
                return new C1(29);
            case 6:
                return new L9(13);
            case 7:
                return new L9(17);
            case 8:
                return com.google.android.gms.ads.internal.j.C.y;
            case 9:
                return new C2615sf();
            case 10:
                return EnumC2515q6.APP_OPEN;
            case 11:
                return "app_open_ad";
            case 12:
                return EnumC2515q6.BANNER;
            case 13:
                return com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_BANNER;
            case 14:
                return new Dg();
            case 15:
                return new Lh();
            case 16:
                Rh rh = new Rh();
                C2601s7 c2601s7 = AbstractC2773w7.k1;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                rh.a = ((Integer) rVar.c.a(c2601s7)).intValue();
                rh.b = ((Integer) rVar.c.a(AbstractC2773w7.Nc)).intValue();
                return rh;
            case 17:
                Set set = Collections.EMPTY_SET;
                AbstractC1981ds.s(set);
                return set;
            case 18:
                Set set2 = Collections.EMPTY_SET;
                AbstractC1981ds.s(set2);
                return set2;
            case 19:
                Set set3 = Collections.EMPTY_SET;
                AbstractC1981ds.s(set3);
                return set3;
            case 20:
                Set set4 = Collections.EMPTY_SET;
                AbstractC1981ds.s(set4);
                return set4;
            case 21:
                Set set5 = Collections.EMPTY_SET;
                AbstractC1981ds.s(set5);
                return set5;
            case EventType.WINDOW_STATE /* 22 */:
                Set set6 = Collections.EMPTY_SET;
                AbstractC1981ds.s(set6);
                return set6;
            case EventType.AUDIO /* 23 */:
                Set set7 = Collections.EMPTY_SET;
                AbstractC1981ds.s(set7);
                return set7;
            case EventType.VIDEO /* 24 */:
                Set set8 = Collections.EMPTY_SET;
                AbstractC1981ds.s(set8);
                return set8;
            case EventType.SUBS /* 25 */:
                return new C2059fi();
            case EventType.CDN /* 26 */:
                return EnumC2515q6.INTERSTITIAL;
            case 27:
                return DTBAdSize.AAX_INTERSTITIAL_AD_SIZE;
            case 28:
                return EnumC2515q6.AD_LOADER;
            default:
                return com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE;
        }
    }

    public H5(Zh zh) {
        this.a = 18;
    }
}
