package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.client.zzt;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class Np implements com.google.android.gms.ads.rewarded.a, InterfaceC2617sh, InterfaceC1840ah, Xg, InterfaceC2102gh, Bh, Bp, InterfaceC2447oi {
    public final C2498pq a;
    public final AtomicReference b = new AtomicReference();
    public final AtomicReference c = new AtomicReference();
    public final AtomicReference d = new AtomicReference();
    public final AtomicReference e = new AtomicReference();
    public final AtomicReference f = new AtomicReference();
    public final AtomicReference g = new AtomicReference();
    public final AtomicReference h = new AtomicReference();
    public final Np i = null;

    public Np(C2498pq c2498pq) {
        this.a = c2498pq;
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void a() {
        Np np = this.i;
        if (np != null) {
            np.a();
            return;
        }
        Os os = this.a.a;
        if (os != null) {
            YF yf = (YF) os.b;
            synchronized (yf) {
                yf.a = 1;
                yf.c();
            }
        }
        Object obj = this.d.get();
        if (obj != null) {
            try {
                ((InterfaceC2569rc) obj).h();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            } catch (NullPointerException e2) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
            }
        }
        Object obj2 = this.e.get();
        if (obj2 == null) {
            return;
        }
        try {
            C2097gc c2097gc = (C2097gc) obj2;
            c2097gc.d4(4, c2097gc.f3());
        } catch (RemoteException e3) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
        } catch (NullPointerException e4) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e4);
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void b() {
        Np np = this.i;
        if (np != null) {
            np.b();
            return;
        }
        Object obj = this.e.get();
        if (obj == null) {
            return;
        }
        try {
            C2097gc c2097gc = (C2097gc) obj;
            c2097gc.d4(6, c2097gc.f3());
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final void c() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final void c0() {
        Np np = this.i;
        if (np != null) {
            np.c0();
        } else {
            AbstractC1972di.h(this.d, new C2147hi(27, (byte) 0));
        }
    }

    @Override // com.google.android.gms.internal.ads.Bh
    public final void d(zzt zztVar) {
        Np np = this.i;
        if (np != null) {
            np.d(zztVar);
            return;
        }
        Object obj = this.h.get();
        if (obj == null) {
            return;
        }
        try {
            ((InterfaceC1609n0) obj).R2(zztVar);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void f() {
        Np np = this.i;
        if (np != null) {
            np.f();
            return;
        }
        Object obj = this.e.get();
        if (obj == null) {
            return;
        }
        try {
            C2097gc c2097gc = (C2097gc) obj;
            c2097gc.d4(3, c2097gc.f3());
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
        }
    }

    @Override // com.google.android.gms.ads.rewarded.a
    public final void j() {
        Np np = this.i;
        if (np != null) {
            np.j();
        } else {
            AbstractC1972di.h(this.b, new C2147hi(26, (byte) 0));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1840ah
    public final void m0(zze zzeVar) {
        Np np = this.i;
        if (np != null) {
            np.m0(zzeVar);
            return;
        }
        AtomicReference atomicReference = this.c;
        Object obj = atomicReference.get();
        if (obj != null) {
            try {
                ((InterfaceC2741vc) obj).r(zzeVar);
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            } catch (NullPointerException e2) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
            }
        }
        Object obj2 = atomicReference.get();
        int i = zzeVar.a;
        if (obj2 != null) {
            try {
                ((InterfaceC2741vc) obj2).u(i);
            } catch (RemoteException e3) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
            } catch (NullPointerException e4) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e4);
            }
        }
        Object obj3 = this.e.get();
        if (obj3 == null) {
            return;
        }
        try {
            C2097gc c2097gc = (C2097gc) obj3;
            Parcel parcelF3 = c2097gc.f3();
            parcelF3.writeInt(i);
            c2097gc.d4(7, parcelF3);
        } catch (RemoteException e5) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e5);
        } catch (NullPointerException e6) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e6);
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void q() {
        Np np = this.i;
        if (np != null) {
            np.q();
            return;
        }
        AtomicReference atomicReference = this.d;
        Object obj = atomicReference.get();
        if (obj != null) {
            try {
                ((InterfaceC2569rc) obj).i();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            } catch (NullPointerException e2) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
            }
        }
        Object obj2 = this.e.get();
        if (obj2 != null) {
            try {
                C2097gc c2097gc = (C2097gc) obj2;
                c2097gc.d4(2, c2097gc.f3());
            } catch (RemoteException e3) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
            } catch (NullPointerException e4) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e4);
            }
        }
        Object obj3 = atomicReference.get();
        if (obj3 == null) {
            return;
        }
        try {
            ((InterfaceC2569rc) obj3).f();
        } catch (RemoteException e5) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e5);
        } catch (NullPointerException e6) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e6);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2102gh
    public final void r(zze zzeVar) {
        Np np = this.i;
        if (np != null) {
            np.r(zzeVar);
            return;
        }
        AtomicReference atomicReference = this.d;
        Object obj = atomicReference.get();
        if (obj != null) {
            try {
                ((InterfaceC2569rc) obj).h3(zzeVar);
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            } catch (NullPointerException e2) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
            }
        }
        Object obj2 = atomicReference.get();
        if (obj2 == null) {
            return;
        }
        try {
            ((InterfaceC2569rc) obj2).k0(zzeVar.a);
        } catch (RemoteException e3) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
        } catch (NullPointerException e4) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e4);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final void s() {
        Np np = this.i;
        if (np != null) {
            np.s();
            return;
        }
        Object obj = this.c.get();
        if (obj != null) {
            try {
                ((InterfaceC2741vc) obj).h();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            } catch (NullPointerException e2) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
            }
        }
        Object obj2 = this.e.get();
        if (obj2 == null) {
            return;
        }
        try {
            C2097gc c2097gc = (C2097gc) obj2;
            c2097gc.d4(1, c2097gc.f3());
        } catch (RemoteException e3) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
        } catch (NullPointerException e4) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e4);
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void v(BinderC1966dc binderC1966dc, String str, String str2) {
        Np np = this.i;
        if (np != null) {
            np.v(binderC1966dc, str, str2);
            return;
        }
        Object obj = this.d.get();
        String str3 = binderC1966dc.a;
        int i = binderC1966dc.b;
        if (obj != null) {
            try {
                ((InterfaceC2569rc) obj).q0(new BinderC2913zc(str3, i));
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            } catch (NullPointerException e2) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
            }
        }
        Object obj2 = this.f.get();
        if (obj2 != null) {
            try {
                C2784wc c2784wc = (C2784wc) obj2;
                BinderC2913zc binderC2913zc = new BinderC2913zc(str3, i);
                Parcel parcelF3 = c2784wc.f3();
                AbstractC2857y5.e(parcelF3, binderC2913zc);
                parcelF3.writeString(str);
                parcelF3.writeString(str2);
                c2784wc.d4(2, parcelF3);
            } catch (RemoteException e3) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
            } catch (NullPointerException e4) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e4);
            }
        }
        Object obj3 = this.e.get();
        if (obj3 != null) {
            try {
                C2097gc c2097gc = (C2097gc) obj3;
                Parcel parcelF32 = c2097gc.f3();
                AbstractC2857y5.e(parcelF32, binderC1966dc);
                c2097gc.d4(5, parcelF32);
            } catch (RemoteException e5) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e5);
            } catch (NullPointerException e6) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e6);
            }
        }
        Object obj4 = this.g.get();
        if (obj4 == null) {
            return;
        }
        try {
            C2053fc c2053fc = (C2053fc) obj4;
            Parcel parcelF33 = c2053fc.f3();
            AbstractC2857y5.e(parcelF33, binderC1966dc);
            parcelF33.writeString(str);
            parcelF33.writeString(str2);
            c2053fc.d4(2, parcelF33);
        } catch (RemoteException e7) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e7);
        } catch (NullPointerException e8) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e8);
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void zze() {
        Np np = this.i;
        if (np != null) {
            np.zze();
            return;
        }
        Object obj = this.e.get();
        if (obj == null) {
            return;
        }
        try {
            C2097gc c2097gc = (C2097gc) obj;
            c2097gc.d4(8, c2097gc.f3());
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
        }
    }
}
