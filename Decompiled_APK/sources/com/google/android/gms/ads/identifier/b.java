package com.google.android.gms.ads.identifier;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.Log;
import androidx.annotation.NonNull;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.google.android.gms.common.internal.u;
import java.io.IOException;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public class b {
    public static final Object h = new Object();
    public static volatile b i;
    public com.google.android.gms.common.a a;
    public com.google.android.gms.internal.ads_identifier.d b;
    public boolean c;
    public final Object d;
    public c e;
    public final Context f;
    public final long g;

    public b(@NonNull Context context) {
        this(context, 30000L);
    }

    public static a a(Context context) {
        b bVar = i;
        if (bVar == null) {
            synchronized (h) {
                try {
                    bVar = i;
                    if (bVar == null) {
                        bVar = new b(context);
                        i = bVar;
                    }
                } finally {
                }
            }
        }
        if (d.c == null) {
            synchronized (d.d) {
                try {
                    if (d.c == null) {
                        d.c = new d(context);
                    }
                } finally {
                }
            }
        }
        d dVar = d.c;
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        try {
            a aVarH = bVar.h();
            long jElapsedRealtime2 = SystemClock.elapsedRealtime() - jElapsedRealtime;
            g(aVarH, jElapsedRealtime2, null);
            dVar.a(0, (int) (SystemClock.elapsedRealtime() - jElapsedRealtime), jElapsedRealtime, System.currentTimeMillis());
            Log.i("AdvertisingIdClient", "GetInfoInternal elapse " + jElapsedRealtime2 + "ms");
            return aVarH;
        } catch (Throwable th) {
            g(null, -1L, th);
            dVar.a(!(th instanceof IOException) ? !(th instanceof GooglePlayServicesNotAvailableException) ? !(th instanceof GooglePlayServicesRepairableException) ? th instanceof IllegalStateException ? 8 : -1 : 16 : 9 : 1, (int) (SystemClock.elapsedRealtime() - jElapsedRealtime), jElapsedRealtime, System.currentTimeMillis());
            throw th;
        }
    }

    public static boolean b(Context context) {
        boolean z;
        b bVar = new b(context, -1L);
        try {
            bVar.e(false);
            u.g("Calling this from your main thread can lead to deadlock");
            synchronized (bVar) {
                bVar.f();
                u.h(bVar.a);
                u.h(bVar.b);
                try {
                    com.google.android.gms.internal.ads_identifier.b bVar2 = (com.google.android.gms.internal.ads_identifier.b) bVar.b;
                    bVar2.getClass();
                    Parcel parcelObtain = Parcel.obtain();
                    parcelObtain.writeInterfaceToken("com.google.android.gms.ads.identifier.internal.IAdvertisingIdService");
                    Parcel parcelV = bVar2.V(6, parcelObtain);
                    int i2 = com.google.android.gms.internal.ads_identifier.a.a;
                    z = parcelV.readInt() != 0;
                    parcelV.recycle();
                } catch (RemoteException e) {
                    Log.i("AdvertisingIdClient", "GMS remote exception ", e);
                    throw new IOException("Remote exception", e);
                }
            }
            bVar.d();
            return z;
        } finally {
            bVar.c();
        }
    }

    public static void g(a aVar, long j, Throwable th) {
        if (Math.random() <= 0.0d) {
            HashMap map = new HashMap();
            map.put("app_context", "1");
            if (aVar != null) {
                map.put("limit_ad_tracking", true != aVar.b ? "0" : "1");
                String str = aVar.a;
                if (str != null) {
                    map.put("ad_id_size", Integer.toString(str.length()));
                }
            }
            if (th != null) {
                map.put("error", th.getClass().getName());
            }
            map.put("tag", "AdvertisingIdClient");
            map.put("time_spent", Long.toString(j));
            new com.amazon.aps.shared.util.a(map, 1).start();
        }
    }

    public final void c() {
        u.g("Calling this from your main thread can lead to deadlock");
        synchronized (this) {
            try {
                if (this.f == null || this.a == null) {
                    return;
                }
                try {
                    if (this.c) {
                        com.google.android.gms.common.stats.a.b().c(this.f, this.a);
                    }
                } catch (Throwable th) {
                    Log.i("AdvertisingIdClient", "AdvertisingIdClient unbindService failed.", th);
                }
                this.c = false;
                this.b = null;
                this.a = null;
            } catch (Throwable th2) {
                throw th2;
            }
        }
    }

    public final void d() {
        synchronized (this.d) {
            c cVar = this.e;
            if (cVar != null) {
                cVar.c.countDown();
                try {
                    this.e.join();
                } catch (InterruptedException unused) {
                }
            }
            long j = this.g;
            if (j > 0) {
                this.e = new c(this, j);
            }
        }
    }

    public final void e(boolean z) {
        IOException iOException;
        u.g("Calling this from your main thread can lead to deadlock");
        if (z) {
            d();
        }
        synchronized (this) {
            try {
                if (this.c) {
                    return;
                }
                Context context = this.f;
                try {
                    context.getPackageManager().getPackageInfo("com.android.vending", 0);
                    int iC = com.google.android.gms.common.c.b.c(context, 12451000);
                    if (iC != 0 && iC != 2) {
                        throw new IOException("Google Play services not available");
                    }
                    com.google.android.gms.common.a aVar = new com.google.android.gms.common.a();
                    Intent intent = new Intent("com.google.android.gms.ads.identifier.service.START");
                    intent.setPackage("com.google.android.gms");
                    try {
                        if (!com.google.android.gms.common.stats.a.b().a(context, intent, aVar, 1)) {
                            throw new IOException("Connection failure");
                        }
                        this.a = aVar;
                        try {
                            try {
                                TimeUnit timeUnit = TimeUnit.MILLISECONDS;
                                IBinder iBinderA = aVar.a();
                                int i2 = com.google.android.gms.internal.ads_identifier.c.a;
                                IInterface iInterfaceQueryLocalInterface = iBinderA.queryLocalInterface("com.google.android.gms.ads.identifier.internal.IAdvertisingIdService");
                                this.b = iInterfaceQueryLocalInterface instanceof com.google.android.gms.internal.ads_identifier.d ? (com.google.android.gms.internal.ads_identifier.d) iInterfaceQueryLocalInterface : new com.google.android.gms.internal.ads_identifier.b(iBinderA);
                                this.c = true;
                            } finally {
                            }
                        } catch (InterruptedException unused) {
                            throw new IOException("Interrupted exception");
                        }
                    } finally {
                    }
                } catch (PackageManager.NameNotFoundException unused2) {
                    throw new GooglePlayServicesNotAvailableException();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final synchronized void f() {
        try {
            if (!this.c) {
                try {
                    e(false);
                    if (!this.c) {
                        throw new IOException("AdvertisingIdClient cannot reconnect.");
                    }
                } catch (Exception e) {
                    throw new IOException("AdvertisingIdClient cannot reconnect.", e);
                }
            }
        } finally {
        }
    }

    public final void finalize() throws Throwable {
        c();
        super.finalize();
    }

    public final a h() {
        a aVar;
        u.g("Calling this from your main thread can lead to deadlock");
        synchronized (this) {
            f();
            u.h(this.a);
            u.h(this.b);
            try {
                com.google.android.gms.internal.ads_identifier.b bVar = (com.google.android.gms.internal.ads_identifier.b) this.b;
                bVar.getClass();
                Parcel parcelObtain = Parcel.obtain();
                parcelObtain.writeInterfaceToken("com.google.android.gms.ads.identifier.internal.IAdvertisingIdService");
                boolean z = true;
                Parcel parcelV = bVar.V(1, parcelObtain);
                String string = parcelV.readString();
                parcelV.recycle();
                com.google.android.gms.internal.ads_identifier.b bVar2 = (com.google.android.gms.internal.ads_identifier.b) this.b;
                bVar2.getClass();
                Parcel parcelObtain2 = Parcel.obtain();
                parcelObtain2.writeInterfaceToken("com.google.android.gms.ads.identifier.internal.IAdvertisingIdService");
                int i2 = com.google.android.gms.internal.ads_identifier.a.a;
                parcelObtain2.writeInt(1);
                Parcel parcelV2 = bVar2.V(2, parcelObtain2);
                if (parcelV2.readInt() == 0) {
                    z = false;
                }
                parcelV2.recycle();
                aVar = new a(string, z);
            } catch (RemoteException e) {
                Log.i("AdvertisingIdClient", "GMS remote exception ", e);
                throw new IOException("Remote exception", e);
            }
        }
        d();
        return aVar;
    }

    public b(Context context, long j) {
        this.d = new Object();
        u.h(context);
        this.f = context.getApplicationContext();
        this.c = false;
        this.g = j;
    }
}
