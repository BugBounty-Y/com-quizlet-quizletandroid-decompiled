package com.google.android.gms.internal.ads;

import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_barcode.C3199m;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3298x5;
import com.google.firebase.messaging.FirebaseMessaging;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.Ud, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC1782Ud implements Runnable {
    public final /* synthetic */ int a;
    public final long b;
    public final Object c;
    public final Object d;
    public final Object e;

    public RunnableC1782Ud(AbstractC1794Wd abstractC1794Wd, String str, String str2, long j) {
        this.a = 0;
        this.c = str;
        this.d = str2;
        this.b = j;
        this.e = abstractC1794Wd;
    }

    public boolean a() {
        ConnectivityManager connectivityManager = (ConnectivityManager) ((FirebaseMessaging) this.d).getApplicationContext().getSystemService("connectivity");
        NetworkInfo activeNetworkInfo = connectivityManager != null ? connectivityManager.getActiveNetworkInfo() : null;
        return activeNetworkInfo != null && activeNetworkInfo.isConnected();
    }

    public boolean b() throws IOException {
        try {
            if (((FirebaseMessaging) this.d).blockingGetToken() == null) {
                Log.e("FirebaseMessaging", "Token retrieval failed: null");
                return false;
            }
            Log.isLoggable("FirebaseMessaging", 3);
            return true;
        } catch (IOException e) {
            String message = e.getMessage();
            if (!"SERVICE_NOT_AVAILABLE".equals(message) && !"INTERNAL_SERVER_ERROR".equals(message) && !"InternalServerError".equals(message)) {
                if (e.getMessage() != null) {
                    throw e;
                }
                Log.w("FirebaseMessaging", "Token retrieval failed without exception message. Will retry token retrieval");
                return false;
            }
            Log.w("FirebaseMessaging", "Token retrieval failed: " + e.getMessage() + ". Will retry token retrieval");
            return false;
        } catch (SecurityException unused) {
            Log.w("FirebaseMessaging", "Token retrieval failed with SecurityException. Will retry token retrieval");
            return false;
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        String str;
        switch (this.a) {
            case 0:
                HashMap map = new HashMap();
                map.put("event", "precacheComplete");
                map.put("src", (String) this.c);
                map.put("cachedSrc", (String) this.d);
                map.put("totalDuration", Long.toString(this.b));
                AbstractC1794Wd.k((AbstractC1794Wd) this.e, map);
                return;
            case 1:
                Xo xo = (Xo) this.c;
                long j = this.b;
                Vo vo = (Vo) this.d;
                Bundle bundle = (Bundle) this.e;
                com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                jVar.k.getClass();
                long jElapsedRealtime = SystemClock.elapsedRealtime() - j;
                if (((Boolean) Y7.a.o()).booleanValue()) {
                    String canonicalName = vo.getClass().getCanonicalName();
                    if (canonicalName == null) {
                        canonicalName = "";
                    }
                    com.google.android.gms.ads.internal.util.A.l("Signal runtime (ms) : " + canonicalName + " = " + jElapsedRealtime);
                }
                C2601s7 c2601s7 = AbstractC2773w7.h2;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                    if (((Boolean) rVar.c.a(AbstractC2773w7.n2)).booleanValue()) {
                        synchronized (xo) {
                            bundle.putLong("sig" + vo.zza(), jElapsedRealtime);
                        }
                    }
                }
                if (((Boolean) rVar.c.a(AbstractC2773w7.f2)).booleanValue()) {
                    Fi fiA = xo.e.a();
                    fiA.o("action", "lat_ms");
                    fiA.o("lat_grp", "sig_lat_grp");
                    fiA.o("lat_id", String.valueOf(vo.zza()));
                    fiA.o("clat_ms", String.valueOf(jElapsedRealtime));
                    if (((Boolean) rVar.c.a(AbstractC2773w7.g2)).booleanValue()) {
                        synchronized (xo) {
                            xo.g++;
                        }
                        C1732Mb c1732Mb = jVar.h.c.c;
                        synchronized (c1732Mb) {
                            str = (String) c1732Mb.c;
                        }
                        fiA.o("seq_num", str);
                        synchronized (xo) {
                            try {
                                if (xo.g == xo.b.size() && xo.f != 0) {
                                    xo.g = 0;
                                    jVar.k.getClass();
                                    String strValueOf = String.valueOf(SystemClock.elapsedRealtime() - xo.f);
                                    if (vo.zza() <= 39 || vo.zza() >= 52) {
                                        fiA.o("lat_clsg", strValueOf);
                                    } else {
                                        fiA.o("lat_gmssg", strValueOf);
                                    }
                                }
                            } finally {
                            }
                        }
                    }
                    ((Hk) fiA.c).b.execute(new Fk(fiA, 1));
                    return;
                }
                return;
            case 2:
                com.google.android.gms.internal.mlkit_vision_barcode.J7 j7 = (com.google.android.gms.internal.mlkit_vision_barcode.J7) this.c;
                HashMap map2 = j7.j;
                EnumC3298x5 enumC3298x5 = EnumC3298x5.AGGREGATED_ON_DEVICE_BARCODE_DETECTION;
                if (!map2.containsKey(enumC3298x5)) {
                    map2.put(enumC3298x5, new C3199m());
                }
                C3199m c3199m = (C3199m) map2.get(enumC3298x5);
                Long lValueOf = Long.valueOf(this.b);
                com.google.android.gms.internal.mlkit_vision_barcode.r rVar2 = c3199m.c;
                com.google.android.gms.internal.mlkit_vision_barcode.W w = (com.google.android.gms.internal.mlkit_vision_barcode.W) this.d;
                Collection collection = (Collection) rVar2.get(w);
                if (collection == null) {
                    ArrayList arrayList = new ArrayList(3);
                    if (!arrayList.add(lValueOf)) {
                        throw new AssertionError("New Collection violated the Collection spec");
                    }
                    rVar2.put(w, arrayList);
                } else {
                    collection.add(lValueOf);
                }
                long jElapsedRealtime2 = SystemClock.elapsedRealtime();
                if (j7.d(enumC3298x5, jElapsedRealtime2)) {
                    j7.i.put(enumC3298x5, Long.valueOf(jElapsedRealtime2));
                    com.google.mlkit.common.sdkinternal.k.a.execute(new androidx.camera.core.impl.utils.futures.h(j7, (com.google.firebase.crashlytics.internal.settings.b) this.e));
                    return;
                }
                return;
            default:
                com.google.firebase.messaging.u uVarD = com.google.firebase.messaging.u.d();
                FirebaseMessaging firebaseMessaging = (FirebaseMessaging) this.d;
                boolean zF = uVarD.f(firebaseMessaging.getApplicationContext());
                PowerManager.WakeLock wakeLock = (PowerManager.WakeLock) this.c;
                if (zF) {
                    wakeLock.acquire();
                }
                try {
                    try {
                        firebaseMessaging.setSyncScheduledOrRunning(true);
                        if (!firebaseMessaging.isGmsCorePresent()) {
                            firebaseMessaging.setSyncScheduledOrRunning(false);
                            if (!com.google.firebase.messaging.u.d().f(firebaseMessaging.getApplicationContext())) {
                                return;
                            }
                        } else if (!com.google.firebase.messaging.u.d().e(firebaseMessaging.getApplicationContext()) || a()) {
                            if (b()) {
                                firebaseMessaging.setSyncScheduledOrRunning(false);
                            } else {
                                firebaseMessaging.syncWithDelaySecondsInternal(this.b);
                            }
                            if (!com.google.firebase.messaging.u.d().f(firebaseMessaging.getApplicationContext())) {
                                return;
                            }
                        } else {
                            com.google.android.gms.common.api.internal.q qVar = new com.google.android.gms.common.api.internal.q();
                            qVar.c = this;
                            qVar.a();
                            if (!com.google.firebase.messaging.u.d().f(firebaseMessaging.getApplicationContext())) {
                                return;
                            }
                        }
                    } catch (IOException e) {
                        Log.e("FirebaseMessaging", "Topic sync or token retrieval failed on hard failure exceptions: " + e.getMessage() + ". Won't retry the operation.");
                        firebaseMessaging.setSyncScheduledOrRunning(false);
                        if (!com.google.firebase.messaging.u.d().f(firebaseMessaging.getApplicationContext())) {
                            return;
                        }
                    }
                    wakeLock.release();
                    return;
                } catch (Throwable th) {
                    if (com.google.firebase.messaging.u.d().f(firebaseMessaging.getApplicationContext())) {
                        wakeLock.release();
                    }
                    throw th;
                }
        }
    }

    public /* synthetic */ RunnableC1782Ud(Xo xo, long j, Vo vo, Bundle bundle) {
        this.a = 1;
        this.c = xo;
        this.b = j;
        this.d = vo;
        this.e = bundle;
    }

    public /* synthetic */ RunnableC1782Ud(com.google.android.gms.internal.mlkit_vision_barcode.J7 j7, com.google.android.gms.internal.mlkit_vision_barcode.W w, long j, com.google.firebase.crashlytics.internal.settings.b bVar) {
        this.a = 2;
        EnumC3298x5 enumC3298x5 = EnumC3298x5.UNKNOWN_EVENT;
        this.c = j7;
        this.d = w;
        this.b = j;
        this.e = bVar;
    }

    public RunnableC1782Ud(FirebaseMessaging firebaseMessaging, long j) {
        this.a = 3;
        this.e = new ThreadPoolExecutor(0, 1, 30L, TimeUnit.SECONDS, new LinkedBlockingQueue(), new com.android.billingclient.api.p("firebase-iid-executor", 2));
        this.d = firebaseMessaging;
        this.b = j;
        PowerManager.WakeLock wakeLockNewWakeLock = ((PowerManager) firebaseMessaging.getApplicationContext().getSystemService("power")).newWakeLock(1, "fiid-sync");
        this.c = wakeLockNewWakeLock;
        wakeLockNewWakeLock.setReferenceCounted(false);
    }
}
