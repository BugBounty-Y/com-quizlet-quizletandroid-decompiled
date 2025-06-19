package com.google.android.gms.internal.ads;

import android.os.ParcelFileDescriptor;
import android.util.Base64;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/* renamed from: com.google.android.gms.internal.ads.pf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2487pf implements Fv {
    public final /* synthetic */ int a;

    public /* synthetic */ C2487pf(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) throws IOException {
        String str = null;
        int i = 1;
        switch (this.a) {
            case 0:
                Throwable th = (Throwable) obj;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.ua)).booleanValue()) {
                    com.google.android.gms.ads.internal.j.C.h.i("GetTopicsApiWithRecordObservationActionHandlerUnsampled", th);
                } else {
                    com.google.android.gms.ads.internal.j.C.h.g("GetTopicsApiWithRecordObservationActionHandler", th);
                }
                C2244ju c2244ju = AbstractC2330lu.b;
                return AbstractC2025es.E(new androidx.privacysandbox.ads.adservices.topics.b(Bu.e));
            case 1:
                com.google.android.gms.ads.internal.util.A.m();
                return Tv.b;
            case 2:
                Throwable cause = (ExecutionException) obj;
                if (cause.getCause() != null) {
                    cause = cause.getCause();
                }
                return AbstractC2025es.C(cause);
            case 3:
                return AbstractC2025es.C(new zzdwf(5));
            case 4:
                return Tv.b;
            case 5:
                return AbstractC2025es.E(((Nl) obj).a);
            case 6:
                Throwable cause2 = (ExecutionException) obj;
                if (cause2.getCause() != null) {
                    cause2 = cause2.getCause();
                }
                return AbstractC2025es.C(cause2);
            case 7:
                ParcelFileDescriptor[] parcelFileDescriptorArrCreatePipe = ParcelFileDescriptor.createPipe();
                ParcelFileDescriptor parcelFileDescriptor = parcelFileDescriptorArrCreatePipe[0];
                AbstractC2270kd.a.execute(new RunnableC2793wl(10, (InputStream) obj, parcelFileDescriptorArrCreatePipe[1]));
                return AbstractC2025es.E(parcelFileDescriptor);
            case 8:
                return AbstractC2025es.E(new C1934co((String) obj, i));
            case 9:
                return ((Throwable) obj) instanceof TimeoutException ? AbstractC2025es.E(new C1934co(Integer.toString(17), i)) : AbstractC2025es.E(new C1934co(str, i));
            case 10:
                com.google.android.gms.appset.b bVar = (com.google.android.gms.appset.b) obj;
                return bVar == null ? AbstractC2025es.E(new C2453oo(null, -1, 0)) : AbstractC2025es.E(new C2453oo(bVar.a, bVar.b, 0));
            case 11:
                androidx.privacysandbox.ads.adservices.topics.b bVar2 = (androidx.privacysandbox.ads.adservices.topics.b) obj;
                if (bVar2 == null) {
                    return AbstractC2025es.E(new C2453oo("", 1, 2));
                }
                GB gbW = HB.w();
                C2244ju c2244juListIterator = bVar2.a.listIterator(0);
                if (!c2244juListIterator.hasNext()) {
                    return AbstractC2025es.E(new C2453oo(Base64.encodeToString(((HB) gbW.c()).d(), 1), 1, 2));
                }
                if (c2244juListIterator.next() != null) {
                    throw new ClassCastException();
                }
                FB.w();
                throw null;
            case 12:
                com.google.android.gms.appset.b bVar3 = (com.google.android.gms.appset.b) obj;
                return bVar3 == null ? AbstractC2025es.E(new C2453oo(null, -1, 3)) : AbstractC2025es.E(new C2453oo(bVar3.a, bVar3.b, 3));
            case 13:
                return Tv.b;
            default:
                return AbstractC2025es.E("");
        }
    }
}
