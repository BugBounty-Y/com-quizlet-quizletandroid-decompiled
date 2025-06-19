package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.client.zzt;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: com.google.android.gms.internal.ads.np, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2411np implements InterfaceC1840ah, InterfaceC2832xh, Bp, com.google.android.gms.ads.internal.overlay.j, Bh, InterfaceC2102gh, InterfaceC2447oi {
    public final C2498pq a;
    public final AtomicReference b = new AtomicReference();
    public final AtomicReference c = new AtomicReference();
    public final AtomicReference d = new AtomicReference();
    public final AtomicReference e = new AtomicReference();
    public final AtomicReference f = new AtomicReference();
    public final AtomicReference g = new AtomicReference();
    public C2411np h = null;

    public C2411np(C2498pq c2498pq) {
        this.a = c2498pq;
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void I3() {
        C2411np c2411np = this.h;
        if (c2411np != null) {
            c2411np.I3();
            return;
        }
        Object obj = this.f.get();
        if (obj != null) {
            try {
                ((com.google.android.gms.ads.internal.overlay.j) obj).I3();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            } catch (NullPointerException e2) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
            }
        }
        AtomicReference atomicReference = this.d;
        Object obj2 = atomicReference.get();
        if (obj2 != null) {
            try {
                ((InterfaceC1953d6) obj2).f();
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
            ((InterfaceC1953d6) obj3).zze();
        } catch (RemoteException e5) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e5);
        } catch (NullPointerException e6) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e6);
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void L2() {
        C2411np c2411np = this.h;
        if (c2411np != null) {
            c2411np.L2();
        } else {
            AbstractC1972di.h(this.f, new C2147hi(24, (byte) 0));
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void X(int i) {
        C2411np c2411np = this.h;
        if (c2411np != null) {
            c2411np.X(i);
            return;
        }
        Object obj = this.f.get();
        if (obj == null) {
            return;
        }
        try {
            ((com.google.android.gms.ads.internal.overlay.j) obj).X(i);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void Y3() {
    }

    public final void a() {
        C2411np c2411np = this.h;
        if (c2411np != null) {
            c2411np.a();
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
        if (this.c.get() != null) {
            try {
                throw new ClassCastException();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            } catch (NullPointerException e2) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
            }
        }
        Object obj = this.d.get();
        if (obj == null) {
            return;
        }
        try {
            ((InterfaceC1953d6) obj).q();
        } catch (RemoteException e3) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
        } catch (NullPointerException e4) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e4);
        }
    }

    public final void b(BinderC1772Sf binderC1772Sf) {
        C2411np c2411np = this.h;
        if (c2411np != null) {
            c2411np.b(binderC1772Sf);
            return;
        }
        Object obj = this.b.get();
        if (obj == null) {
            return;
        }
        try {
            ((InterfaceC1866b6) obj).a4(binderC1772Sf);
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
        C2411np c2411np = this.h;
        if (c2411np != null) {
            c2411np.c0();
            return;
        }
        Object obj = this.d.get();
        if (obj == null) {
            return;
        }
        try {
            ((InterfaceC1953d6) obj).b();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
        }
    }

    @Override // com.google.android.gms.internal.ads.Bh
    public final void d(zzt zztVar) {
        C2411np c2411np = this.h;
        if (c2411np != null) {
            c2411np.d(zztVar);
            return;
        }
        Object obj = this.g.get();
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

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void f3() {
        C2411np c2411np = this.h;
        if (c2411np != null) {
            c2411np.f3();
        } else {
            AbstractC1972di.h(this.f, new C2147hi(22, (byte) 0));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2832xh
    public final void h() {
        C2411np c2411np = this.h;
        if (c2411np != null) {
            c2411np.h();
        } else {
            AbstractC1972di.h(this.e, new C2147hi(23, (byte) 0));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1840ah
    public final void m0(zze zzeVar) {
        C2411np c2411np = this.h;
        if (c2411np != null) {
            c2411np.m0(zzeVar);
            return;
        }
        AtomicReference atomicReference = this.b;
        Object obj = atomicReference.get();
        if (obj != null) {
            try {
                ((InterfaceC1866b6) obj).a0(zzeVar);
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
            ((InterfaceC1866b6) obj2).F(zzeVar.a);
        } catch (RemoteException e3) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
        } catch (NullPointerException e4) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e4);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2102gh
    public final void r(zze zzeVar) {
        C2411np c2411np = this.h;
        if (c2411np != null) {
            c2411np.r(zzeVar);
            return;
        }
        Object obj = this.d.get();
        if (obj == null) {
            return;
        }
        try {
            ((InterfaceC1953d6) obj).S(zzeVar);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void v3() {
    }
}
