package com.google.android.play.core.review.internal;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import com.android.billingclient.api.C1472a;
import com.android.billingclient.api.u;
import com.comscore.LiveTransmissionMode;
import java.util.HashMap;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class i extends e {
    public final /* synthetic */ int b = 0;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public i(u uVar, IBinder iBinder) {
        this.c = iBinder;
        this.d = uVar;
    }

    @Override // com.google.android.play.core.review.internal.e
    public final void a() throws RemoteException {
        HashMap map;
        d bVar = null;
        switch (this.b) {
            case 0:
                int i = c.b;
                IBinder iBinder = (IBinder) this.c;
                if (iBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.play.core.inappreview.protocol.IInAppReviewService");
                    bVar = iInterfaceQueryLocalInterface instanceof d ? (d) iInterfaceQueryLocalInterface : new b(iBinder);
                }
                j jVar = (j) ((u) this.d).b;
                jVar.m = bVar;
                C1472a c1472a = jVar.b;
                c1472a.a("linkToDeath", new Object[0]);
                try {
                    ((b) jVar.m).a.linkToDeath(jVar.j, 0);
                } catch (RemoteException e) {
                    Object[] objArr = new Object[0];
                    c1472a.getClass();
                    if (Log.isLoggable("PlayCore", 6)) {
                        Log.e("PlayCore", C1472a.c(c1472a.b, "linkToDeath failed", objArr), e);
                    }
                }
                jVar.g = false;
                Iterator it2 = jVar.d.iterator();
                while (it2.hasNext()) {
                    ((Runnable) it2.next()).run();
                }
                jVar.d.clear();
                return;
            default:
                try {
                    com.google.android.play.core.review.d dVar = (com.google.android.play.core.review.d) this.d;
                    d dVar2 = dVar.a.m;
                    String str = dVar.b;
                    Bundle bundle = new Bundle();
                    HashMap map2 = com.google.android.play.core.review.e.a;
                    synchronized (com.google.android.play.core.review.e.class) {
                        map = com.google.android.play.core.review.e.a;
                        map.put("java", Integer.valueOf(LiveTransmissionMode.LAN));
                    }
                    bundle.putInt("playcore_version_code", ((Integer) map.get("java")).intValue());
                    if (map.containsKey(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE)) {
                        bundle.putInt("playcore_native_version", ((Integer) map.get(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE)).intValue());
                    }
                    if (map.containsKey("unity")) {
                        bundle.putInt("playcore_unity_version", ((Integer) map.get("unity")).intValue());
                    }
                    com.google.android.play.core.review.d dVar3 = (com.google.android.play.core.review.d) this.d;
                    com.google.android.gms.tasks.f fVar = (com.google.android.gms.tasks.f) this.c;
                    String str2 = dVar3.b;
                    com.google.android.play.core.review.c cVar = new com.google.android.play.core.review.c(dVar3, fVar);
                    b bVar2 = (b) dVar2;
                    bVar2.getClass();
                    Parcel parcelObtain = Parcel.obtain();
                    parcelObtain.writeInterfaceToken("com.google.android.play.core.inappreview.protocol.IInAppReviewService");
                    parcelObtain.writeString(str);
                    int i2 = a.a;
                    parcelObtain.writeInt(1);
                    bundle.writeToParcel(parcelObtain, 0);
                    parcelObtain.writeStrongBinder(cVar);
                    try {
                        bVar2.a.transact(2, parcelObtain, null, 1);
                        parcelObtain.recycle();
                        return;
                    } catch (Throwable th) {
                        parcelObtain.recycle();
                        throw th;
                    }
                } catch (RemoteException e2) {
                    com.google.android.play.core.review.d dVar4 = (com.google.android.play.core.review.d) this.d;
                    C1472a c1472a2 = com.google.android.play.core.review.d.c;
                    Object[] objArr2 = {dVar4.b};
                    c1472a2.getClass();
                    if (Log.isLoggable("PlayCore", 6)) {
                        Log.e("PlayCore", C1472a.c(c1472a2.b, "error requesting in-app review for %s", objArr2), e2);
                    }
                    ((com.google.android.gms.tasks.f) this.c).c(new RuntimeException(e2));
                    return;
                }
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(com.google.android.play.core.review.d dVar, com.google.android.gms.tasks.f fVar, com.google.android.gms.tasks.f fVar2) {
        super(fVar);
        this.c = fVar2;
        this.d = dVar;
    }
}
