package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import android.util.Pair;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.client.zzt;
import java.util.Iterator;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class Ln implements com.google.android.gms.ads.admanager.a, Jh, InterfaceC2617sh, InterfaceC1840ah, InterfaceC2189ih, InterfaceC1582a, Xg, Bh, InterfaceC2102gh, InterfaceC2447oi {
    public final Hk i;
    public final AtomicReference a = new AtomicReference();
    public final AtomicReference b = new AtomicReference();
    public final AtomicReference c = new AtomicReference();
    public final AtomicReference d = new AtomicReference();
    public final AtomicReference e = new AtomicReference();
    public final AtomicBoolean f = new AtomicBoolean(true);
    public final AtomicBoolean g = new AtomicBoolean(false);
    public final AtomicBoolean h = new AtomicBoolean(false);
    public final ArrayBlockingQueue j = new ArrayBlockingQueue(((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.R8)).intValue());

    public Ln(Hk hk) {
        this.i = hk;
    }

    public final void A() {
        if (this.g.get() && this.h.get()) {
            ArrayBlockingQueue arrayBlockingQueue = this.j;
            Iterator it2 = arrayBlockingQueue.iterator();
            while (it2.hasNext()) {
                Pair pair = (Pair) it2.next();
                Object obj = this.b.get();
                if (obj != null) {
                    try {
                        ((com.google.android.gms.ads.internal.client.P) obj).b3((String) pair.first, (String) pair.second);
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
                    } catch (NullPointerException e2) {
                        com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
                    }
                }
            }
            arrayBlockingQueue.clear();
            this.f.set(false);
        }
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void J0(C1849aq c1849aq) {
        this.f.set(true);
        this.h.set(false);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final void K() {
        AbstractC1972di.h(this.a, new C2147hi(21, (byte) 0));
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void a() {
        Object obj = this.a.get();
        if (obj != null) {
            try {
                ((InterfaceC1622x) obj).j();
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
            ((com.google.android.gms.ads.internal.client.V) obj2).q();
        } catch (RemoteException e3) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
        } catch (NullPointerException e4) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e4);
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void b() {
        Object obj = this.a.get();
        if (obj == null) {
            return;
        }
        try {
            ((InterfaceC1622x) obj).g();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final void c() {
        Object obj = this.a.get();
        if (obj == null) {
            return;
        }
        try {
            ((InterfaceC1622x) obj).t();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final void c0() {
        Object obj;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.La)).booleanValue() && (obj = this.a.get()) != null) {
            try {
                ((InterfaceC1622x) obj).q();
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
            ((com.google.android.gms.ads.internal.client.V) obj2).b();
        } catch (RemoteException e3) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
        } catch (NullPointerException e4) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e4);
        }
    }

    @Override // com.google.android.gms.internal.ads.Bh
    public final void d(zzt zztVar) {
        Object obj = this.c.get();
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
    }

    public final synchronized InterfaceC1622x j() {
        return (InterfaceC1622x) this.a.get();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1840ah
    public final void m0(zze zzeVar) {
        AtomicReference atomicReference = this.a;
        Object obj = atomicReference.get();
        if (obj != null) {
            try {
                ((InterfaceC1622x) obj).r(zzeVar);
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            } catch (NullPointerException e2) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
            }
        }
        Object obj2 = atomicReference.get();
        if (obj2 != null) {
            try {
                ((InterfaceC1622x) obj2).u(zzeVar.a);
            } catch (RemoteException e3) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
            } catch (NullPointerException e4) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e4);
            }
        }
        Object obj3 = this.d.get();
        if (obj3 != null) {
            try {
                ((com.google.android.gms.ads.internal.client.A) obj3).t2(zzeVar);
            } catch (RemoteException e5) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e5);
            } catch (NullPointerException e6) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e6);
            }
        }
        this.f.set(false);
        this.j.clear();
    }

    public final void o(com.google.android.gms.ads.internal.client.P p) {
        this.b.set(p);
        this.g.set(true);
        A();
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final void onAdClicked() {
        Object obj;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.La)).booleanValue() || (obj = this.a.get()) == null) {
            return;
        }
        try {
            ((InterfaceC1622x) obj).q();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
        }
    }

    @Override // com.google.android.gms.ads.admanager.a
    public final synchronized void onAppEvent(String str, String str2) {
        if (!this.f.get()) {
            Object obj = this.b.get();
            if (obj != null) {
                try {
                    ((com.google.android.gms.ads.internal.client.P) obj).b3(str, str2);
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
                } catch (NullPointerException e2) {
                    com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
                }
            }
            return;
        }
        if (!this.j.offer(new Pair(str, str2))) {
            com.google.android.gms.ads.internal.util.client.i.d("The queue for app events is full, dropping the new event.");
            Hk hk = this.i;
            if (hk != null) {
                Fi fiA = hk.a();
                fiA.o("action", "dae_action");
                fiA.o("dae_name", str);
                fiA.o("dae_data", str2);
                fiA.x();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void q() {
        Object obj = this.a.get();
        if (obj != null) {
            try {
                ((InterfaceC1622x) obj).i();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            } catch (NullPointerException e2) {
                com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
            }
        }
        AtomicReference atomicReference = this.e;
        Object obj2 = atomicReference.get();
        if (obj2 != null) {
            try {
                ((com.google.android.gms.ads.internal.client.V) obj2).f();
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
            ((com.google.android.gms.ads.internal.client.V) obj3).zze();
        } catch (RemoteException e5) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e5);
        } catch (NullPointerException e6) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e6);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2102gh
    public final void r(zze zzeVar) {
        Object obj = this.e.get();
        if (obj == null) {
            return;
        }
        try {
            ((com.google.android.gms.ads.internal.client.V) obj).S(zzeVar);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
        }
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void r0(zzbvl zzbvlVar) {
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0039 A[Catch: all -> 0x0044, TRY_LEAVE, TryCatch #2 {, blocks: (B:3:0x0001, B:6:0x000a, B:12:0x001d, B:15:0x0026, B:21:0x0039, B:18:0x002d, B:20:0x0034, B:9:0x0011, B:11:0x0018), top: B:27:0x0001, inners: #3, #4, #5 }] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0026 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized void s() {
        /*
            r2 = this;
            monitor-enter(r2)
            java.util.concurrent.atomic.AtomicReference r0 = r2.a     // Catch: java.lang.Throwable -> L44
            java.lang.Object r0 = r0.get()     // Catch: java.lang.Throwable -> L44
            if (r0 != 0) goto La
            goto L1d
        La:
            com.google.android.gms.ads.internal.client.x r0 = (com.google.android.gms.ads.internal.client.InterfaceC1622x) r0     // Catch: java.lang.NullPointerException -> L10 android.os.RemoteException -> L17 java.lang.Throwable -> L44
            r0.zzi()     // Catch: java.lang.NullPointerException -> L10 android.os.RemoteException -> L17 java.lang.Throwable -> L44
            goto L1d
        L10:
            r0 = move-exception
            java.lang.String r1 = "NullPointerException occurs when invoking a method from a delegating listener."
            com.google.android.gms.ads.internal.util.client.i.i(r1, r0)     // Catch: java.lang.Throwable -> L44
            goto L1d
        L17:
            r0 = move-exception
            java.lang.String r1 = "#007 Could not call remote method."
            com.google.android.gms.ads.internal.util.client.i.j(r1, r0)     // Catch: java.lang.Throwable -> L44
        L1d:
            java.util.concurrent.atomic.AtomicReference r0 = r2.d     // Catch: java.lang.Throwable -> L44
            java.lang.Object r0 = r0.get()     // Catch: java.lang.Throwable -> L44
            if (r0 != 0) goto L26
            goto L39
        L26:
            com.google.android.gms.ads.internal.client.A r0 = (com.google.android.gms.ads.internal.client.A) r0     // Catch: java.lang.NullPointerException -> L2c android.os.RemoteException -> L33 java.lang.Throwable -> L44
            r0.q()     // Catch: java.lang.NullPointerException -> L2c android.os.RemoteException -> L33 java.lang.Throwable -> L44
            goto L39
        L2c:
            r0 = move-exception
            java.lang.String r1 = "NullPointerException occurs when invoking a method from a delegating listener."
            com.google.android.gms.ads.internal.util.client.i.i(r1, r0)     // Catch: java.lang.Throwable -> L44
            goto L39
        L33:
            r0 = move-exception
            java.lang.String r1 = "#007 Could not call remote method."
            com.google.android.gms.ads.internal.util.client.i.j(r1, r0)     // Catch: java.lang.Throwable -> L44
        L39:
            java.util.concurrent.atomic.AtomicBoolean r0 = r2.h     // Catch: java.lang.Throwable -> L44
            r1 = 1
            r0.set(r1)     // Catch: java.lang.Throwable -> L44
            r2.A()     // Catch: java.lang.Throwable -> L44
            monitor-exit(r2)
            return
        L44:
            r0 = move-exception
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L44
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Ln.s():void");
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void v(BinderC1966dc binderC1966dc, String str, String str2) {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void zze() {
    }
}
