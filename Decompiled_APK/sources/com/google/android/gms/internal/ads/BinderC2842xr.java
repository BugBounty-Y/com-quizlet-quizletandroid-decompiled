package com.google.android.gms.internal.ads;

import android.net.ConnectivityManager;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zzfp;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: com.google.android.gms.internal.ads.xr, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2842xr extends AbstractBinderC2814x5 {
    public final C2928zr a;

    public BinderC2842xr(C2928zr c2928zr) {
        super("com.google.android.gms.ads.internal.client.IAdPreloader");
        this.a = c2928zr;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        com.google.android.gms.ads.internal.client.N n;
        Y5 y5;
        boolean zG;
        com.google.android.gms.ads.internal.client.K k;
        switch (i) {
            case 1:
                ArrayList arrayListCreateTypedArrayList = parcel.createTypedArrayList(zzfp.CREATOR);
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder == null) {
                    n = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdPreloadCallback");
                    n = iInterfaceQueryLocalInterface instanceof com.google.android.gms.ads.internal.client.N ? (com.google.android.gms.ads.internal.client.N) iInterfaceQueryLocalInterface : new com.google.android.gms.ads.internal.client.N(strongBinder, "com.google.android.gms.ads.internal.client.IAdPreloadCallback", 0);
                }
                AbstractC2857y5.b(parcel);
                f4(arrayListCreateTypedArrayList, n);
                parcel2.writeNoException();
                return true;
            case 2:
                String string = parcel.readString();
                AbstractC2857y5.b(parcel);
                boolean zH4 = h4(string);
                parcel2.writeNoException();
                parcel2.writeInt(zH4 ? 1 : 0);
                return true;
            case 3:
                String string2 = parcel.readString();
                AbstractC2857y5.b(parcel);
                InterfaceC2441oc interfaceC2441ocE4 = e4(string2);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2441ocE4);
                return true;
            case 4:
                String string3 = parcel.readString();
                AbstractC2857y5.b(parcel);
                boolean zG4 = g4(string3);
                parcel2.writeNoException();
                parcel2.writeInt(zG4 ? 1 : 0);
                return true;
            case 5:
                String string4 = parcel.readString();
                AbstractC2857y5.b(parcel);
                C2928zr c2928zr = this.a;
                synchronized (c2928zr) {
                    y5 = (Y5) c2928zr.d(Y5.class, string4, com.google.android.gms.ads.c.APP_OPEN_AD);
                }
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, y5);
                return true;
            case 6:
                String string5 = parcel.readString();
                AbstractC2857y5.b(parcel);
                C2928zr c2928zr2 = this.a;
                synchronized (c2928zr2) {
                    zG = c2928zr2.g(string5, com.google.android.gms.ads.c.INTERSTITIAL);
                }
                parcel2.writeNoException();
                parcel2.writeInt(zG ? 1 : 0);
                return true;
            case 7:
                String string6 = parcel.readString();
                AbstractC2857y5.b(parcel);
                C2928zr c2928zr3 = this.a;
                synchronized (c2928zr3) {
                    k = (com.google.android.gms.ads.internal.client.K) c2928zr3.d(com.google.android.gms.ads.internal.client.K.class, string6, com.google.android.gms.ads.c.INTERSTITIAL);
                }
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, k);
                return true;
            case 8:
                InterfaceC2825xa interfaceC2825xaE4 = BinderC2739va.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                C2928zr c2928zr4 = this.a;
                c2928zr4.c.e = interfaceC2825xaE4;
                if (c2928zr4.f == null) {
                    synchronized (c2928zr4) {
                        if (c2928zr4.f == null) {
                            try {
                                c2928zr4.f = (ConnectivityManager) c2928zr4.e.getSystemService("connectivity");
                            } catch (ClassCastException e) {
                                com.google.android.gms.ads.internal.util.client.i.i("Failed to get connectivity manager", e);
                            }
                        }
                    }
                }
                if (c2928zr4.f == null) {
                    c2928zr4.h = new AtomicInteger(((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.B)).intValue());
                } else {
                    try {
                        c2928zr4.f.registerDefaultNetworkCallback(new androidx.work.impl.constraints.d(c2928zr4, 5));
                    } catch (RuntimeException e2) {
                        com.google.android.gms.ads.internal.util.client.i.i("Failed to register network callback", e2);
                        c2928zr4.h = new AtomicInteger(((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.B)).intValue());
                    }
                }
                com.google.android.gms.ads.internal.j.C.g.l(new C1996e6(c2928zr4, 1));
                parcel2.writeNoException();
                return true;
            default:
                return false;
        }
    }

    public final InterfaceC2441oc e4(String str) {
        InterfaceC2441oc interfaceC2441oc;
        C2928zr c2928zr = this.a;
        synchronized (c2928zr) {
            interfaceC2441oc = (InterfaceC2441oc) c2928zr.d(InterfaceC2441oc.class, str, com.google.android.gms.ads.c.REWARDED);
        }
        return interfaceC2441oc;
    }

    public final void f4(ArrayList arrayList, com.google.android.gms.ads.internal.client.N n) {
        EnumMap enumMap;
        zzfp zzfpVar;
        String str;
        com.google.android.gms.ads.c cVarA;
        Fi fi;
        int i = 0;
        C2928zr c2928zr = this.a;
        synchronized (c2928zr) {
            try {
                ArrayList arrayListE = c2928zr.e(arrayList);
                enumMap = new EnumMap(com.google.android.gms.ads.c.class);
                Iterator it2 = arrayListE.iterator();
                while (it2.hasNext()) {
                    zzfpVar = (zzfp) it2.next();
                    str = zzfpVar.a;
                    cVarA = com.google.android.gms.ads.c.a(zzfpVar.b);
                    C2670tr c2670trA = c2928zr.c.a(zzfpVar, n);
                    if (cVarA != null && c2670trA != null) {
                        AtomicInteger atomicInteger = c2928zr.h;
                        if (atomicInteger != null) {
                            int i2 = atomicInteger.get();
                            synchronized (c2670trA) {
                                com.google.android.gms.common.internal.u.b(i2 >= 5);
                                C2713ur c2713ur = c2670trA.i;
                                synchronized (c2713ur) {
                                    com.google.android.gms.common.internal.u.b(i2 > 0);
                                    c2713ur.d = i2;
                                }
                            }
                        }
                        fi = c2928zr.d;
                        c2670trA.n = fi;
                        String strA = C2928zr.a(str, cVarA);
                        synchronized (c2928zr) {
                            synchronized (c2670trA) {
                                c2670trA.k.submit(new Dr(c2670trA, i));
                            }
                            c2928zr.a.put(strA, c2670trA);
                        }
                    }
                }
                c2928zr.d.v(enumMap, c2928zr.g.currentTimeMillis());
                return;
            } catch (Throwable th) {
                throw th;
            }
        }
        Ls ls = com.google.android.gms.ads.internal.util.client.c.b;
        enumMap.put((EnumMap) cVarA, (com.google.android.gms.ads.c) Integer.valueOf(((Integer) (enumMap.containsKey(cVarA) ? enumMap.get(cVarA) : 0)).intValue() + 1));
        fi.w(zzfpVar.d, c2928zr.g.currentTimeMillis(), new Ar(new Fp(str, false, cVarA, 3)));
    }

    public final boolean g4(String str) {
        boolean zG;
        C2928zr c2928zr = this.a;
        synchronized (c2928zr) {
            zG = c2928zr.g(str, com.google.android.gms.ads.c.APP_OPEN_AD);
        }
        return zG;
    }

    public final boolean h4(String str) {
        boolean zG;
        C2928zr c2928zr = this.a;
        synchronized (c2928zr) {
            zG = c2928zr.g(str, com.google.android.gms.ads.c.REWARDED);
        }
        return zG;
    }
}
