package com.google.android.gms.cloudmessaging;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.media.metrics.LogSessionId;
import android.media.metrics.MediaMetricsManager;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Log;
import androidx.core.view.AbstractC1042d;
import com.android.billingclient.api.p;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.AbstractC2096gb;
import com.google.android.gms.internal.ads.C1874bE;
import com.google.android.gms.internal.ads.C1917cE;
import com.google.android.gms.internal.ads.C2221jD;
import com.google.android.gms.internal.ads.Sq;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.InterfaceC3897v;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.Y0;
import com.google.android.gms.measurement.internal.zzai;
import com.google.android.gms.measurement.internal.zzbh;
import com.google.android.gms.measurement.internal.zzqb;
import com.google.android.gms.measurement.internal.zzr;
import com.google.firebase.iid.FirebaseInstanceIdReceiver;
import java.lang.ref.SoftReference;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final /* synthetic */ class g implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ g(Context context, boolean z, C2221jD c2221jD, C1917cE c1917cE) {
        this.a = 1;
        this.b = context;
        this.c = z;
        this.d = c2221jD;
        this.e = c1917cE;
    }

    @Override // java.lang.Runnable
    public final void run() throws Throwable {
        Executor executorUnconfigurableExecutorService;
        int iA;
        switch (this.a) {
            case 0:
                Intent intent = (Intent) this.d;
                Context context = (Context) this.b;
                boolean z = this.c;
                BroadcastReceiver.PendingResult pendingResult = (BroadcastReceiver.PendingResult) this.e;
                try {
                    Parcelable parcelableExtra = intent.getParcelableExtra("wrapped_intent");
                    Intent intent2 = parcelableExtra instanceof Intent ? (Intent) parcelableExtra : null;
                    if (intent2 != null) {
                        iA = FirebaseInstanceIdReceiver.a(intent2);
                    } else {
                        Bundle extras = intent.getExtras();
                        int iIntValue = com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR;
                        if (extras != null) {
                            CloudMessage cloudMessage = new CloudMessage(intent);
                            CountDownLatch countDownLatch = new CountDownLatch(1);
                            synchronized (FirebaseInstanceIdReceiver.class) {
                                try {
                                    SoftReference softReference = FirebaseInstanceIdReceiver.b;
                                    executorUnconfigurableExecutorService = softReference != null ? (Executor) softReference.get() : null;
                                    if (executorUnconfigurableExecutorService == null) {
                                        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(1, 1, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue(), new p("pscm-ack-executor", 2));
                                        threadPoolExecutor.allowCoreThreadTimeOut(true);
                                        executorUnconfigurableExecutorService = Executors.unconfigurableExecutorService(threadPoolExecutor);
                                        FirebaseInstanceIdReceiver.b = new SoftReference(executorUnconfigurableExecutorService);
                                    }
                                } finally {
                                }
                            }
                            executorUnconfigurableExecutorService.execute(new androidx.core.provider.k(context, cloudMessage, countDownLatch, 10));
                            try {
                                iIntValue = ((Integer) S3.e(new com.google.firebase.messaging.h(context).b(intent))).intValue();
                            } catch (InterruptedException | ExecutionException e) {
                                Log.e("FirebaseMessaging", "Failed to send message to service.", e);
                            }
                            try {
                                if (!countDownLatch.await(TimeUnit.SECONDS.toMillis(1L), TimeUnit.MILLISECONDS)) {
                                    Log.w("CloudMessagingReceiver", "Message ack timed out");
                                }
                            } catch (InterruptedException e2) {
                                Log.w("CloudMessagingReceiver", "Message ack failed: ".concat(e2.toString()));
                            }
                        }
                        iA = iIntValue;
                    }
                    if (z && pendingResult != null) {
                        pendingResult.setResultCode(iA);
                    }
                    if (pendingResult != null) {
                        pendingResult.finish();
                        return;
                    }
                    return;
                } catch (Throwable th) {
                    if (pendingResult != null) {
                        pendingResult.finish();
                    }
                    throw th;
                }
            case 1:
                Context context2 = (Context) this.b;
                MediaMetricsManager mediaMetricsManagerI = AbstractC1042d.i(context2.getSystemService("media_metrics"));
                C1874bE c1874bE = mediaMetricsManagerI == null ? null : new C1874bE(context2, mediaMetricsManagerI.createPlaybackSession());
                if (c1874bE == null) {
                    AbstractC2096gb.J("ExoPlayerImpl", "MediaMetricsService unavailable.");
                    return;
                }
                if (this.c) {
                    ((C2221jD) this.d).E1(c1874bE);
                }
                C1917cE c1917cE = (C1917cE) this.e;
                LogSessionId sessionId = c1874bE.d.getSessionId();
                synchronized (c1917cE) {
                    Sq sq = c1917cE.b;
                    if (sq == null) {
                        throw null;
                    }
                    LogSessionId logSessionId = (LogSessionId) sq.a;
                    LogSessionId unused = LogSessionId.LOG_SESSION_ID_NONE;
                    AbstractC1795We.L(logSessionId.equals(LogSessionId.LOG_SESSION_ID_NONE));
                    sq.a = sessionId;
                }
                return;
            case 2:
                Y0 y0 = (Y0) this.e;
                InterfaceC3897v interfaceC3897v = y0.e;
                if (interfaceC3897v == null) {
                    I i = ((Y) y0.b).i;
                    Y.k(i);
                    i.g.f("Discarding data. Failed to set user property");
                    return;
                } else {
                    y0.Y(interfaceC3897v, this.c ? null : (zzqb) this.b, (zzr) this.d);
                    y0.h0();
                    return;
                }
            case 3:
                Y0 y02 = (Y0) this.e;
                InterfaceC3897v interfaceC3897v2 = y02.e;
                if (interfaceC3897v2 == null) {
                    I i2 = ((Y) y02.b).i;
                    Y.k(i2);
                    i2.g.f("Discarding data. Failed to send event to service");
                    return;
                } else {
                    y02.Y(interfaceC3897v2, this.c ? null : (zzbh) this.b, (zzr) this.d);
                    y02.h0();
                    return;
                }
            default:
                Y0 y03 = (Y0) this.e;
                InterfaceC3897v interfaceC3897v3 = y03.e;
                if (interfaceC3897v3 == null) {
                    I i3 = ((Y) y03.b).i;
                    Y.k(i3);
                    i3.g.f("Discarding data. Failed to send conditional user property to service");
                    return;
                } else {
                    y03.Y(interfaceC3897v3, this.c ? null : (zzai) this.b, (zzr) this.d);
                    y03.h0();
                    return;
                }
        }
    }

    public /* synthetic */ g(Y0 y0, zzr zzrVar, boolean z, AbstractSafeParcelable abstractSafeParcelable, int i) {
        this.a = i;
        this.d = zzrVar;
        this.c = z;
        this.b = abstractSafeParcelable;
        this.e = y0;
    }

    public /* synthetic */ g(FirebaseInstanceIdReceiver firebaseInstanceIdReceiver, Intent intent, Context context, boolean z, BroadcastReceiver.PendingResult pendingResult) {
        this.a = 0;
        this.d = intent;
        this.b = context;
        this.c = z;
        this.e = pendingResult;
    }
}
