package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.zw, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2933zw implements InterfaceC2334ly {
    public static final C2933zw b = new C2933zw(0);
    public static final C2163hy c = new C2163hy(Nx.class, InterfaceC2289kw.class, new Is(12));
    public static final C2933zw d = new C2933zw(1);
    public static final C2933zw e = new C2933zw(2);
    public static final C2163hy f = new C2163hy(Nx.class, InterfaceC2504pw.class, new C2806wy(3));
    public final /* synthetic */ int a;

    public /* synthetic */ C2933zw(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2334ly
    public final Object a(C2326lq c2326lq, Px px, Fp fp) throws GeneralSecurityException {
        C2604sA c2604sAR;
        List arrayList;
        C2604sA c2604sAR2;
        List list;
        C2604sA c2604sAR3;
        List list2;
        switch (this.a) {
            case 0:
                HashMap map = new HashMap();
                for (int i = 0; i < ((List) c2326lq.c).size(); i++) {
                    C2418nw c2418nwM = c2326lq.m(i);
                    if (c2418nwM.b.equals(C2332lw.c)) {
                        AbstractC2025es abstractC2025es = c2418nwM.a;
                        if (abstractC2025es instanceof AbstractC2761vw) {
                            c2604sAR = ((AbstractC2761vw) abstractC2025es).R();
                        } else {
                            if (!(abstractC2025es instanceof Nx)) {
                                throw new GeneralSecurityException(android.support.v4.media.session.a.m("Cannot get output prefix for key of class ", abstractC2025es.getClass().getName(), " with parameters ", String.valueOf(abstractC2025es.g())));
                            }
                            c2604sAR = ((Nx) abstractC2025es).d;
                        }
                        C2847xw c2847xw = new C2847xw((InterfaceC2289kw) fp.a(c2418nwM), c2418nwM.c);
                        byte[] bArr = c2604sAR.a;
                        if (bArr.length != 0 && bArr.length != 5) {
                            throw new GeneralSecurityException("PrefixMap only supports 0 and 5 byte prefixes");
                        }
                        if (map.containsKey(c2604sAR)) {
                            arrayList = (List) map.get(c2604sAR);
                        } else {
                            arrayList = new ArrayList();
                            map.put(c2604sAR, arrayList);
                        }
                        arrayList.add(c2847xw);
                    }
                }
                if (!px.a.isEmpty()) {
                    Tx tx = (Tx) Ux.b.a.get();
                    if (tx == null) {
                        tx = Ux.c;
                    }
                    tx.getClass();
                }
                c2326lq.p();
                return new C2890yw(new C2119gy(map));
            case 1:
                C2418nw c2418nwP = c2326lq.p();
                HashMap map2 = new HashMap();
                for (int i2 = 0; i2 < ((List) c2326lq.c).size(); i2++) {
                    C2418nw c2418nwM2 = c2326lq.m(i2);
                    if (c2418nwM2.b.equals(C2332lw.c)) {
                        C2935zy c2935zy = (C2935zy) fp.a(c2418nwM2);
                        AbstractC2025es abstractC2025es2 = c2418nwM2.a;
                        if (abstractC2025es2 instanceof Gy) {
                            c2604sAR2 = ((Gy) abstractC2025es2).R();
                        } else {
                            if (!(abstractC2025es2 instanceof Nx)) {
                                throw new GeneralSecurityException(android.support.v4.media.session.a.m("Cannot get output prefix for key of class ", abstractC2025es2.getClass().getName(), " with parameters ", String.valueOf(abstractC2025es2.g())));
                            }
                            c2604sAR2 = ((Nx) abstractC2025es2).d;
                        }
                        byte[] bArr2 = c2604sAR2.a;
                        if (bArr2.length != 0 && bArr2.length != 5) {
                            throw new GeneralSecurityException("PrefixMap only supports 0 and 5 byte prefixes");
                        }
                        if (map2.containsKey(c2604sAR2)) {
                            list = (List) map2.get(c2604sAR2);
                        } else {
                            ArrayList arrayList2 = new ArrayList();
                            map2.put(c2604sAR2, arrayList2);
                            list = arrayList2;
                        }
                        list.add(c2935zy);
                    }
                }
                return new C2935zy();
            default:
                HashMap map3 = new HashMap();
                for (int i3 = 0; i3 < ((List) c2326lq.c).size(); i3++) {
                    C2418nw c2418nwM3 = c2326lq.m(i3);
                    if (c2418nwM3.b.equals(C2332lw.c)) {
                        AbstractC2025es abstractC2025es3 = c2418nwM3.a;
                        if (abstractC2025es3 instanceof Gy) {
                            c2604sAR3 = ((Gy) abstractC2025es3).R();
                        } else {
                            if (!(abstractC2025es3 instanceof Nx)) {
                                throw new GeneralSecurityException(android.support.v4.media.session.a.m("Cannot get output prefix for key of class ", abstractC2025es3.getClass().getName(), " with parameters ", String.valueOf(abstractC2025es3.g())));
                            }
                            c2604sAR3 = ((Nx) abstractC2025es3).d;
                        }
                        C2806wy c2806wy = new C2806wy(4);
                        byte[] bArr3 = c2604sAR3.a;
                        if (bArr3.length != 0 && bArr3.length != 5) {
                            throw new GeneralSecurityException("PrefixMap only supports 0 and 5 byte prefixes");
                        }
                        if (map3.containsKey(c2604sAR3)) {
                            list2 = (List) map3.get(c2604sAR3);
                        } else {
                            ArrayList arrayList3 = new ArrayList();
                            map3.put(c2604sAR3, arrayList3);
                            list2 = arrayList3;
                        }
                        list2.add(c2806wy);
                    }
                }
                if (!px.a.isEmpty()) {
                    Tx tx2 = (Tx) Ux.b.a.get();
                    if (tx2 == null) {
                        tx2 = Ux.c;
                    }
                    tx2.getClass();
                }
                c2326lq.p();
                return new Iy();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2334ly
    public final Class zza() {
        switch (this.a) {
            case 0:
                return InterfaceC2289kw.class;
            case 1:
                return C2935zy.class;
            default:
                return InterfaceC2504pw.class;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2334ly
    public final Class zzb() {
        switch (this.a) {
            case 0:
                return InterfaceC2289kw.class;
            case 1:
                return C2935zy.class;
            default:
                return InterfaceC2504pw.class;
        }
    }
}
