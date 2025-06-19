package com.google.android.gms.common.internal;

import android.accounts.Account;
import android.content.AttributionSource;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.DeadObjectException;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: com.google.android.gms.common.internal.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1655e {
    public static final Feature[] y = new Feature[0];
    public volatile String a;
    public androidx.room.s b;
    public final Context c;
    public final E d;
    public final com.google.android.gms.common.c e;
    public final w f;
    public final Object g;
    public final Object h;
    public q i;
    public InterfaceC1654d j;
    public IInterface k;
    public final ArrayList l;
    public y m;
    public int n;
    public final InterfaceC1652b o;
    public final InterfaceC1653c p;
    public final int q;
    public final String r;
    public volatile String s;
    public volatile com.google.firebase.platforminfo.c t;
    public ConnectionResult u;
    public boolean v;
    public volatile zzj w;
    public final AtomicInteger x;

    /* JADX WARN: Illegal instructions before constructor call */
    public AbstractC1655e(int i, Context context, Looper looper, InterfaceC1652b interfaceC1652b, InterfaceC1653c interfaceC1653c) {
        E eA = E.a(context);
        com.google.android.gms.common.c cVar = com.google.android.gms.common.c.b;
        u.h(interfaceC1652b);
        u.h(interfaceC1653c);
        this(context, looper, eA, cVar, i, interfaceC1652b, interfaceC1653c, null);
    }

    public int a() {
        return com.google.android.gms.common.c.a;
    }

    public boolean b() {
        return false;
    }

    public final void c() {
        int iC = this.e.c(this.c, a());
        if (iC == 0) {
            this.j = new i(this);
            w(2, null);
            return;
        }
        w(1, null);
        this.j = new i(this);
        int i = this.x.get();
        w wVar = this.f;
        wVar.sendMessage(wVar.obtainMessage(3, i, iC, null));
    }

    public abstract IInterface d(IBinder iBinder);

    public void e() {
        this.x.incrementAndGet();
        ArrayList arrayList = this.l;
        synchronized (arrayList) {
            try {
                int size = arrayList.size();
                for (int i = 0; i < size; i++) {
                    p pVar = (p) arrayList.get(i);
                    synchronized (pVar) {
                        pVar.a = null;
                    }
                }
                arrayList.clear();
            } catch (Throwable th) {
                throw th;
            }
        }
        synchronized (this.h) {
            this.i = null;
        }
        w(1, null);
    }

    public final void f(String str) {
        this.a = str;
        e();
    }

    public Account g() {
        return null;
    }

    public Feature[] h() {
        return y;
    }

    public Executor i() {
        return null;
    }

    public Bundle j() {
        return new Bundle();
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void k(InterfaceC1657g interfaceC1657g, Set set) {
        AttributionSource attributionSource;
        Bundle bundleJ = j();
        String attributionTag = (Build.VERSION.SDK_INT < 31 || this.t == null || (attributionSource = (AttributionSource) this.t.a) == null || attributionSource.getAttributionTag() == null) ? this.s : attributionSource.getAttributionTag();
        String str = attributionTag;
        int i = this.q;
        int i2 = com.google.android.gms.common.c.a;
        Scope[] scopeArr = GetServiceRequest.o;
        Bundle bundle = new Bundle();
        Feature[] featureArr = GetServiceRequest.p;
        GetServiceRequest getServiceRequest = new GetServiceRequest(6, i, i2, null, null, scopeArr, bundle, null, featureArr, featureArr, true, 0, false, str);
        getServiceRequest.d = this.c.getPackageName();
        getServiceRequest.g = bundleJ;
        if (set != null) {
            getServiceRequest.f = (Scope[]) set.toArray(new Scope[0]);
        }
        if (b()) {
            Account accountG = g();
            if (accountG == null) {
                accountG = new Account("<<default account>>", "com.google");
            }
            getServiceRequest.h = accountG;
            if (interfaceC1657g != 0) {
                getServiceRequest.e = ((AbstractC2771w5) interfaceC1657g).b;
            }
        }
        getServiceRequest.i = y;
        getServiceRequest.j = h();
        if (s()) {
            getServiceRequest.m = true;
        }
        try {
            synchronized (this.h) {
                try {
                    q qVar = this.i;
                    if (qVar != null) {
                        qVar.V(new x(this, this.x.get()), getServiceRequest);
                    } else {
                        Log.w("GmsClient", "mServiceBroker is null, client disconnected");
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        } catch (DeadObjectException e) {
            Log.w("GmsClient", "IGmsServiceBroker.getService failed", e);
            int i3 = this.x.get();
            w wVar = this.f;
            wVar.sendMessage(wVar.obtainMessage(6, i3, 3));
        } catch (RemoteException e2) {
            e = e2;
            Log.w("GmsClient", "IGmsServiceBroker.getService failed", e);
            int i4 = this.x.get();
            z zVar = new z(this, 8, null, null);
            w wVar2 = this.f;
            wVar2.sendMessage(wVar2.obtainMessage(1, i4, -1, zVar));
        } catch (SecurityException e3) {
            throw e3;
        } catch (RuntimeException e4) {
            e = e4;
            Log.w("GmsClient", "IGmsServiceBroker.getService failed", e);
            int i42 = this.x.get();
            z zVar2 = new z(this, 8, null, null);
            w wVar22 = this.f;
            wVar22.sendMessage(wVar22.obtainMessage(1, i42, -1, zVar2));
        }
    }

    public Set l() {
        return Collections.EMPTY_SET;
    }

    public final IInterface m() {
        IInterface iInterface;
        synchronized (this.g) {
            try {
                if (this.n == 5) {
                    throw new DeadObjectException();
                }
                if (!q()) {
                    throw new IllegalStateException("Not connected. Call connect() and wait for onConnected() to be called.");
                }
                iInterface = this.k;
                u.i(iInterface, "Client is connected but service is null");
            } catch (Throwable th) {
                throw th;
            }
        }
        return iInterface;
    }

    public abstract String n();

    public abstract String o();

    public boolean p() {
        return a() >= 211700000;
    }

    public final boolean q() {
        boolean z;
        synchronized (this.g) {
            z = this.n == 4;
        }
        return z;
    }

    public final boolean r() {
        boolean z;
        synchronized (this.g) {
            int i = this.n;
            z = true;
            if (i != 2 && i != 3) {
                z = false;
            }
        }
        return z;
    }

    public boolean s() {
        return this instanceof com.google.android.gms.auth.blockstore.restorecredential.internal.a;
    }

    public final /* synthetic */ boolean t(int i, int i2, IInterface iInterface) {
        synchronized (this.g) {
            try {
                if (this.n != i) {
                    return false;
                }
                w(i2, iInterface);
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final /* synthetic */ void u() {
        int i;
        int i2;
        synchronized (this.g) {
            i = this.n;
        }
        if (i == 3) {
            this.v = true;
            i2 = 5;
        } else {
            i2 = 4;
        }
        w wVar = this.f;
        wVar.sendMessage(wVar.obtainMessage(i2, this.x.get(), 16));
    }

    public final /* synthetic */ boolean v() throws ClassNotFoundException {
        if (this.v || TextUtils.isEmpty(n()) || TextUtils.isEmpty(null)) {
            return false;
        }
        try {
            Class.forName(n());
            return true;
        } catch (ClassNotFoundException unused) {
            return false;
        }
    }

    public final void w(int i, IInterface iInterface) {
        androidx.room.s sVar;
        u.b((i == 4) == (iInterface != null));
        synchronized (this.g) {
            try {
                this.n = i;
                this.k = iInterface;
                Bundle bundle = null;
                if (i == 1) {
                    y yVar = this.m;
                    if (yVar != null) {
                        E e = this.d;
                        String str = this.b.b;
                        u.h(str);
                        this.b.getClass();
                        if (this.r == null) {
                            this.c.getClass();
                        }
                        e.c(str, yVar, this.b.c);
                        this.m = null;
                    }
                } else if (i == 2 || i == 3) {
                    y yVar2 = this.m;
                    if (yVar2 != null && (sVar = this.b) != null) {
                        String str2 = sVar.b;
                        StringBuilder sb = new StringBuilder(String.valueOf(str2).length() + 70 + "com.google.android.gms".length());
                        sb.append("Calling connect() while still connected, missing disconnect() for ");
                        sb.append(str2);
                        sb.append(" on com.google.android.gms");
                        Log.e("GmsClient", sb.toString());
                        E e2 = this.d;
                        String str3 = this.b.b;
                        u.h(str3);
                        this.b.getClass();
                        if (this.r == null) {
                            this.c.getClass();
                        }
                        e2.c(str3, yVar2, this.b.c);
                        this.x.incrementAndGet();
                    }
                    y yVar3 = new y(this, this.x.get());
                    this.m = yVar3;
                    String strO = o();
                    boolean zP = p();
                    this.b = new androidx.room.s(strO, 3, zP);
                    if (zP && a() < 17895000) {
                        throw new IllegalStateException("Internal Error, the minimum apk version of this BaseGmsClient is too low to support dynamic lookup. Start service action: ".concat(String.valueOf(this.b.b)));
                    }
                    E e3 = this.d;
                    String str4 = this.b.b;
                    u.h(str4);
                    this.b.getClass();
                    String name = this.r;
                    if (name == null) {
                        name = this.c.getClass().getName();
                    }
                    ConnectionResult connectionResultB = e3.b(new B(str4, this.b.c), yVar3, name, i());
                    if (!(connectionResultB.b == 0)) {
                        String str5 = this.b.b;
                        StringBuilder sb2 = new StringBuilder(String.valueOf(str5).length() + 34 + "com.google.android.gms".length());
                        sb2.append("unable to connect to service: ");
                        sb2.append(str5);
                        sb2.append(" on com.google.android.gms");
                        Log.w("GmsClient", sb2.toString());
                        int i2 = connectionResultB.b;
                        if (i2 == -1) {
                            i2 = 16;
                        }
                        if (connectionResultB.c != null) {
                            bundle = new Bundle();
                            bundle.putParcelable("pendingIntent", connectionResultB.c);
                        }
                        int i3 = this.x.get();
                        A a = new A(this, i2, bundle);
                        w wVar = this.f;
                        wVar.sendMessage(wVar.obtainMessage(7, i3, -1, a));
                    }
                } else if (i == 4) {
                    u.h(iInterface);
                    System.currentTimeMillis();
                }
            } finally {
            }
        }
    }

    public AbstractC1655e(Context context, Looper looper, E e, com.google.android.gms.common.c cVar, int i, InterfaceC1652b interfaceC1652b, InterfaceC1653c interfaceC1653c, String str) {
        this.a = null;
        this.g = new Object();
        this.h = new Object();
        this.l = new ArrayList();
        this.n = 1;
        this.u = null;
        this.v = false;
        this.w = null;
        this.x = new AtomicInteger(0);
        u.i(context, "Context must not be null");
        this.c = context;
        u.i(looper, "Looper must not be null");
        u.i(e, "Supervisor must not be null");
        this.d = e;
        u.i(cVar, "API availability must not be null");
        this.e = cVar;
        this.f = new w(this, looper);
        this.q = i;
        this.o = interfaceC1652b;
        this.p = interfaceC1653c;
        this.r = str;
    }
}
