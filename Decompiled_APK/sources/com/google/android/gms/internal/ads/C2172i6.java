package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import com.comscore.streaming.ContentType;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.internal.InterfaceC1652b;
import com.google.android.gms.common.internal.InterfaceC1653c;
import com.google.android.gms.common.internal.zzj;

/* renamed from: com.google.android.gms.internal.ads.i6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2172i6 extends com.google.android.gms.ads.internal.b {
    public final /* synthetic */ int z = 1;

    public /* synthetic */ C2172i6(int i, Context context, Looper looper, InterfaceC1652b interfaceC1652b, InterfaceC1653c interfaceC1653c) {
        super(i, context, looper, interfaceC1652b, interfaceC1653c);
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e, com.google.android.gms.common.api.c
    public int a() {
        switch (this.z) {
            case 2:
                return 243734000;
            default:
                return super.a();
        }
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final IInterface d(IBinder iBinder) {
        switch (this.z) {
            case 0:
                if (iBinder == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.cache.ICacheService");
                return iInterfaceQueryLocalInterface instanceof C2214j6 ? (C2214j6) iInterfaceQueryLocalInterface : new C2214j6(iBinder, "com.google.android.gms.ads.internal.cache.ICacheService", 0);
            case 1:
                if (iBinder == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface2 = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.httpcache.IHttpAssetsCacheService");
                return iInterfaceQueryLocalInterface2 instanceof B9 ? (B9) iInterfaceQueryLocalInterface2 : new B9(iBinder, "com.google.android.gms.ads.internal.httpcache.IHttpAssetsCacheService", 0);
            default:
                if (iBinder == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface3 = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.request.IAdRequestService");
                return iInterfaceQueryLocalInterface3 instanceof InterfaceC1774Tb ? (InterfaceC1774Tb) iInterfaceQueryLocalInterface3 : new C1768Sb(iBinder, "com.google.android.gms.ads.internal.request.IAdRequestService", 0);
        }
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public Feature[] h() {
        switch (this.z) {
            case 0:
                return com.google.android.gms.ads.w.b;
            default:
                return super.h();
        }
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String n() {
        switch (this.z) {
            case 0:
                return "com.google.android.gms.ads.internal.cache.ICacheService";
            case 1:
                return "com.google.android.gms.ads.internal.httpcache.IHttpAssetsCacheService";
            default:
                return "com.google.android.gms.ads.internal.request.IAdRequestService";
        }
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String o() {
        switch (this.z) {
            case 0:
                return "com.google.android.gms.ads.service.CACHE";
            case 1:
                return "com.google.android.gms.ads.service.HTTP";
            default:
                return "com.google.android.gms.ads.service.START";
        }
    }

    public boolean x() {
        zzj zzjVar = this.w;
        Feature[] featureArr = zzjVar == null ? null : zzjVar.b;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T1)).booleanValue()) {
            Feature feature = com.google.android.gms.ads.w.a;
            int length = featureArr != null ? featureArr.length : 0;
            int i = 0;
            while (true) {
                if (i >= length) {
                    break;
                }
                if (!com.google.android.gms.common.internal.u.l(featureArr[i], feature)) {
                    i++;
                } else if (i >= 0) {
                    return true;
                }
            }
        }
        return false;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C2172i6(Context context, Looper looper, InterfaceC1652b interfaceC1652b, InterfaceC1653c interfaceC1653c) {
        int i = AbstractC2009ec.a;
        Context applicationContext = context.getApplicationContext();
        super(ContentType.USER_GENERATED_LIVE, applicationContext == null ? context : applicationContext, looper, interfaceC1652b, interfaceC1653c);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public C2172i6(Context context, Looper looper, Hl hl, Hl hl2) {
        int i = AbstractC2009ec.a;
        Context applicationContext = context.getApplicationContext();
        super(8, applicationContext == null ? context : applicationContext, looper, hl, hl2);
    }
}
