package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.formats.AdManagerAdViewOptions;
import com.google.android.gms.ads.formats.PublisherAdViewOptions;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.ads.internal.client.zzfw;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class Hn extends com.google.android.gms.ads.internal.client.F {
    public final Context a;
    public final C1765Re b;
    public final C1979dq c;
    public final C2210j2 d;
    public InterfaceC1622x e;

    public Hn(C1765Re c1765Re, Context context, String str) {
        C1979dq c1979dq = new C1979dq();
        this.c = c1979dq;
        this.d = new C2210j2();
        this.b = c1765Re;
        c1979dq.c = str;
        this.a = context;
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void G3(com.google.android.gms.ads.internal.client.T t) {
        this.c.u = t;
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void J0(L8 l8) {
        this.d.a = l8;
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void J1(zzbfv zzbfvVar) {
        this.c.h = zzbfvVar;
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void K1(K8 k8) {
        this.d.b = k8;
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void O3(zzbmg zzbmgVar) {
        C1979dq c1979dq = this.c;
        c1979dq.n = zzbmgVar;
        c1979dq.d = new zzfw(false, true, false);
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void P3(PublisherAdViewOptions publisherAdViewOptions) {
        C1979dq c1979dq = this.c;
        c1979dq.k = publisherAdViewOptions;
        if (publisherAdViewOptions != null) {
            c1979dq.e = publisherAdViewOptions.a;
            c1979dq.l = publisherAdViewOptions.b;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void S3(AdManagerAdViewOptions adManagerAdViewOptions) {
        C1979dq c1979dq = this.c;
        c1979dq.j = adManagerAdViewOptions;
        if (adManagerAdViewOptions != null) {
            c1979dq.e = adManagerAdViewOptions.a;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void U2(InterfaceC1622x interfaceC1622x) {
        this.e = interfaceC1622x;
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void W2(P9 p9) {
        this.d.e = p9;
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void i3(String str, P8 p8, N8 n8) {
        C2210j2 c2210j2 = this.d;
        ((androidx.collection.V) c2210j2.f).put(str, p8);
        if (n8 != null) {
            ((androidx.collection.V) c2210j2.g).put(str, n8);
        }
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void m3(S8 s8, com.google.android.gms.ads.internal.client.zzr zzrVar) {
        this.d.d = s8;
        this.c.b = zzrVar;
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final void o3(U8 u8) {
        this.d.c = u8;
    }

    @Override // com.google.android.gms.ads.internal.client.G
    public final com.google.android.gms.ads.internal.client.D zze() {
        C2210j2 c2210j2 = this.d;
        c2210j2.getClass();
        C1929cj c1929cj = new C1929cj(c2210j2);
        ArrayList arrayList = new ArrayList();
        if (c1929cj.c != null) {
            arrayList.add(Integer.toString(6));
        }
        if (c1929cj.a != null) {
            arrayList.add(Integer.toString(1));
        }
        if (c1929cj.b != null) {
            arrayList.add(Integer.toString(2));
        }
        androidx.collection.V v = c1929cj.f;
        if (!v.isEmpty()) {
            arrayList.add(Integer.toString(3));
        }
        if (c1929cj.e != null) {
            arrayList.add(Integer.toString(7));
        }
        C1979dq c1979dq = this.c;
        c1979dq.f = arrayList;
        ArrayList arrayList2 = new ArrayList(v.c);
        for (int i = 0; i < v.c; i++) {
            arrayList2.add((String) v.g(i));
        }
        c1979dq.g = arrayList2;
        if (c1979dq.b == null) {
            c1979dq.b = com.google.android.gms.ads.internal.client.zzr.b();
        }
        return new In(this.a, this.b, c1979dq, c1929cj, this.e);
    }
}
