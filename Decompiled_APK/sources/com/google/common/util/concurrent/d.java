package com.google.common.util.concurrent;

import android.R;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.graphics.drawable.BitmapDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.Log;
import android.util.SparseArray;
import android.widget.ProgressBar;
import androidx.appcompat.app.ExecutorC0060p;
import androidx.camera.camera2.internal.p0;
import androidx.compose.foundation.gestures.l1;
import androidx.core.app.AbstractC1018e;
import androidx.core.app.C1017d;
import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.C1433e;
import androidx.work.impl.F;
import androidx.work.impl.G;
import androidx.work.impl.model.v;
import com.android.billingclient.api.C1473b;
import com.android.billingclient.api.k;
import com.bumptech.glide.load.engine.m;
import com.bumptech.glide.load.engine.n;
import com.bumptech.glide.load.engine.o;
import com.bumptech.glide.request.g;
import com.bumptech.glide.util.f;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import com.google.android.gms.ads.internal.client.C0;
import com.google.android.gms.ads.internal.j;
import com.google.android.gms.ads.internal.util.C1633i;
import com.google.android.gms.ads.internal.util.RunnableC1626b;
import com.google.android.gms.ads.nonagon.signalgeneration.C1635a;
import com.google.android.gms.ads.nonagon.signalgeneration.s;
import com.google.android.gms.cloudmessaging.h;
import com.google.android.gms.cloudmessaging.i;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.api.GoogleApiActivity;
import com.google.android.gms.common.api.internal.C1643a;
import com.google.android.gms.common.api.internal.C1647e;
import com.google.android.gms.common.api.internal.D;
import com.google.android.gms.common.api.internal.l;
import com.google.android.gms.common.api.internal.q;
import com.google.android.gms.common.internal.AbstractC1655e;
import com.google.android.gms.common.internal.AbstractC1656f;
import com.google.android.gms.common.internal.InterfaceC1657g;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.Hk;
import com.google.android.gms.internal.ads.Ls;
import com.google.android.gms.internal.mlkit_vision_camera.A2;
import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.measurement.internal.A;
import com.google.android.gms.measurement.internal.AbstractC3876k;
import com.google.android.gms.measurement.internal.BinderC3869g0;
import com.google.android.gms.measurement.internal.D0;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.InterfaceC3873i0;
import com.google.android.gms.measurement.internal.O;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.r1;
import com.google.android.gms.measurement.internal.x1;
import com.google.android.gms.measurement.internal.zzai;
import com.google.android.gms.measurement.internal.zzov;
import com.google.android.gms.measurement.internal.zzqb;
import com.google.android.gms.measurement.internal.zzr;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.r;
import kotlinx.coroutines.C5028l;
import org.json.JSONException;

/* loaded from: classes2.dex */
public final class d implements Runnable {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ d(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    private final void a() {
        g gVar = (g) this.b;
        gVar.a.a();
        synchronized (gVar.b) {
            synchronized (((o) this.c)) {
                try {
                    n nVar = ((o) this.c).a;
                    g gVar2 = (g) this.b;
                    nVar.getClass();
                    if (((ArrayList) nVar.b).contains(new m(gVar2, f.b))) {
                        ((o) this.c).s.b();
                        o oVar = (o) this.c;
                        g gVar3 = (g) this.b;
                        oVar.getClass();
                        try {
                            gVar3.h(oVar.s, oVar.o, oVar.v);
                            ((o) this.c).h((g) this.b);
                        } catch (Throwable th) {
                            throw new com.bumptech.glide.load.engine.b(th);
                        }
                    }
                    ((o) this.c).d();
                } catch (Throwable th2) {
                    throw th2;
                }
            }
        }
    }

    private final void b() {
        C0 c0 = (C0) this.b;
        Activity activity = (Activity) this.c;
        synchronized (c0.e) {
            c0.b(activity);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0088  */
    /* JADX WARN: Removed duplicated region for block: B:32:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final void c() throws org.json.JSONException {
        /*
            r8 = this;
            java.lang.Object r0 = r8.b
            com.google.android.gms.ads.nonagon.signalgeneration.r r0 = (com.google.android.gms.ads.nonagon.signalgeneration.r) r0
            java.lang.Object r1 = r8.c
            com.google.android.gms.ads.nonagon.signalgeneration.q r1 = (com.google.android.gms.ads.nonagon.signalgeneration.q) r1
            com.google.android.gms.ads.nonagon.signalgeneration.k r2 = r0.a
            java.lang.String r0 = r0.c
            r2.getClass()
            boolean r3 = android.text.TextUtils.isEmpty(r0)
            if (r3 != 0) goto L9e
            boolean r3 = r2.b()
            if (r3 == 0) goto L1d
            goto L9e
        L1d:
            org.json.JSONObject r3 = new org.json.JSONObject
            r3.<init>()
            org.json.JSONObject r4 = new org.json.JSONObject     // Catch: org.json.JSONException -> L4d
            r4.<init>()     // Catch: org.json.JSONException -> L4d
            java.lang.String r5 = "params"
            java.lang.String r6 = r1.a     // Catch: org.json.JSONException -> L4d
            r4.put(r5, r6)     // Catch: org.json.JSONException -> L4d
            java.lang.String r5 = "signal_dictionary"
            com.google.android.gms.ads.internal.client.q r6 = com.google.android.gms.ads.internal.client.C1614q.f     // Catch: org.json.JSONException -> L4d
            com.google.android.gms.ads.internal.util.client.c r6 = r6.a     // Catch: org.json.JSONException -> L4d
            android.os.Bundle r7 = r1.f     // Catch: org.json.JSONException -> L4d
            org.json.JSONObject r6 = r6.h(r7)     // Catch: org.json.JSONException -> L4d
            r4.put(r5, r6)     // Catch: org.json.JSONException -> L4d
            java.lang.String r5 = "sr"
            r3.put(r5, r4)     // Catch: org.json.JSONException -> L4d
            java.lang.String r1 = r1.c     // Catch: org.json.JSONException -> L4d
            boolean r4 = android.text.TextUtils.isEmpty(r1)     // Catch: org.json.JSONException -> L4d
            if (r4 == 0) goto L4f
            java.lang.String r1 = ""
            goto L82
        L4d:
            r1 = move-exception
            goto L75
        L4f:
            java.lang.String r1 = com.google.android.gms.ads.nonagon.signalgeneration.k.a(r1)     // Catch: org.json.JSONException -> L4d
            java.nio.charset.Charset r4 = java.nio.charset.StandardCharsets.UTF_8     // Catch: org.json.JSONException -> L4d
            byte[] r1 = r1.getBytes(r4)     // Catch: org.json.JSONException -> L4d
            r4 = 10
            java.lang.String r1 = android.util.Base64.encodeToString(r1, r4)     // Catch: org.json.JSONException -> L4d
            java.lang.String r4 = "rs"
            r3.put(r4, r1)     // Catch: org.json.JSONException -> L4d
            java.lang.String r1 = "ts_ms"
            com.google.android.gms.ads.internal.j r4 = com.google.android.gms.ads.internal.j.C     // Catch: org.json.JSONException -> L4d
            com.google.android.gms.common.util.b r4 = r4.k     // Catch: org.json.JSONException -> L4d
            r4.getClass()     // Catch: org.json.JSONException -> L4d
            long r4 = java.lang.System.currentTimeMillis()     // Catch: org.json.JSONException -> L4d
            r3.put(r1, r4)     // Catch: org.json.JSONException -> L4d
            goto L7e
        L75:
            java.lang.String r4 = "DiskCachingManager.createStringToWrite"
            com.google.android.gms.ads.internal.j r5 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.internal.ads.ed r5 = r5.h
            r5.h(r4, r1)
        L7e:
            java.lang.String r1 = r3.toString()
        L82:
            boolean r3 = android.text.TextUtils.isEmpty(r1)
            if (r3 != 0) goto L9e
            com.google.android.gms.ads.nonagon.signalgeneration.u r2 = r2.b
            r2.e()
            java.lang.Object r3 = r2.d
            monitor-enter(r3)
            android.content.SharedPreferences$Editor r2 = r2.b     // Catch: java.lang.Throwable -> L9b
            android.content.SharedPreferences$Editor r0 = r2.putString(r0, r1)     // Catch: java.lang.Throwable -> L9b
            r0.commit()     // Catch: java.lang.Throwable -> L9b
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L9b
            goto L9e
        L9b:
            r0 = move-exception
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L9b
            throw r0
        L9e:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.common.util.concurrent.d.c():void");
    }

    private final void d() {
        i iVar = (i) this.b;
        IBinder iBinder = (IBinder) this.c;
        synchronized (iVar) {
            if (iBinder == null) {
                iVar.a("Null service connection");
                return;
            }
            try {
                iVar.c = new v(iBinder);
                iVar.a = 2;
                ((ScheduledExecutorService) iVar.f.d).execute(new h(iVar, 0));
            } catch (RemoteException e) {
                iVar.a(e.getMessage());
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v7, types: [com.google.android.gms.common.api.internal.g, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r4v13, types: [com.google.android.gms.common.api.internal.g, java.lang.Object] */
    private final void e() {
        boolean z = false;
        l lVar = (l) this.c;
        if (lVar.b) {
            D d = (D) this.b;
            ConnectionResult connectionResult = d.b;
            if ((connectionResult.b == 0 || connectionResult.c == null) ? false : true) {
                ?? r4 = lVar.a;
                Activity activityA = lVar.a();
                PendingIntent pendingIntent = connectionResult.c;
                u.h(pendingIntent);
                int i = d.a;
                int i2 = GoogleApiActivity.b;
                Intent intent = new Intent(activityA, (Class<?>) GoogleApiActivity.class);
                intent.putExtra("pending_intent", pendingIntent);
                intent.putExtra("failing_client_id", i);
                intent.putExtra("notify_manager", false);
                r4.startActivityForResult(intent, 1);
                return;
            }
            Activity activityA2 = lVar.a();
            int i3 = connectionResult.b;
            GoogleApiAvailability googleApiAvailability = lVar.e;
            if (googleApiAvailability.b(activityA2, null, i3) != null) {
                googleApiAvailability.f(lVar.a(), lVar.a, connectionResult.b, lVar);
                return;
            }
            if (connectionResult.b != 18) {
                int i4 = d.a;
                lVar.c.set(null);
                lVar.g.h(connectionResult, i4);
                return;
            }
            Activity activityA3 = lVar.a();
            ProgressBar progressBar = new ProgressBar(activityA3, null, R.attr.progressBarStyleLarge);
            progressBar.setIndeterminate(true);
            progressBar.setVisibility(0);
            AlertDialog.Builder builder = new AlertDialog.Builder(activityA3);
            builder.setView(progressBar);
            builder.setMessage(com.google.android.gms.common.internal.l.b(activityA3, 18));
            builder.setPositiveButton("", (DialogInterface.OnClickListener) null);
            AlertDialog alertDialogCreate = builder.create();
            GoogleApiAvailability.h(activityA3, alertDialogCreate, "GooglePlayServicesUpdatingDialog", lVar);
            Context applicationContext = lVar.a().getApplicationContext();
            com.quizlet.data.repository.qclass.c cVar = new com.quizlet.data.repository.qclass.c(this, z, alertDialogCreate, 9);
            IntentFilter intentFilter = new IntentFilter("android.intent.action.PACKAGE_ADDED");
            intentFilter.addDataScheme("package");
            q qVar = new q(cVar);
            androidx.core.content.c.f(applicationContext, qVar, intentFilter, 2);
            qVar.b = applicationContext;
            if (com.google.android.gms.common.d.c(applicationContext)) {
                return;
            }
            l lVar2 = (l) this.c;
            lVar2.c.set(null);
            Ls ls = lVar2.g.n;
            ls.sendMessage(ls.obtainMessage(3));
            if (alertDialogCreate.isShowing()) {
                alertDialogCreate.dismiss();
            }
            synchronized (qVar) {
                try {
                    Context context = qVar.b;
                    if (context != null) {
                        context.unregisterReceiver(qVar);
                    }
                    qVar.b = null;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    /* JADX WARN: Can't wrap try/catch for region: R(16:298|(11:300|(1:305)|332|(1:334)|335|388|336|337|338|343|(5:349|(1:351)(1:352)|(1:356)|(1:358)|359))(1:306)|307|(2:309|(2:315|316)(3:312|(1:314)(0)|316))(1:317)|(5:319|(1:321)(1:322)|323|(1:325)|326)(1:327)|328|(1:330)(1:331)|332|(0)|335|388|336|337|338|343|(7:345|347|349|(0)(0)|(2:354|356)|(0)|359)(0)) */
    /* JADX WARN: Can't wrap try/catch for region: R(25:24|(1:26)(31:29|392|30|31|(1:34)(27:36|(1:38)|390|39|(7:41|(1:43)(1:45)|386|46|396|47|48)|28|52|(1:63)(4:56|(1:58)(1:59)|60|(1:62)(0))|64|(2:66|(2:68|(2:70|(2:72|(2:74|(2:76|(1:78)(1:79))(1:80))(1:81))(1:82))(1:83))(1:84))(1:85)|86|(1:88)|394|89|(1:91)(1:92)|93|(13:97|(1:99)(1:100)|101|(2:106|107)(3:400|104|107)|116|118|(1:120)(7:122|(0)(1:125)|(3:398|127|(1:129)(1:130))(0)|(2:136|(1:138)(4:139|(3:142|(1:409)(1:410)|140)|408|145))(1:145)|(1:147)(1:148)|149|(30:151|(2:153|(1:155)(1:156))|157|(1:159)|160|(2:162|(1:164)(1:165))(0)|166|(2:168|(4:173|(1:175)|176|(1:178))(1:(5:172|173|(0)|176|(0))))(0)|179|(20:184|(1:186)|(1:218)|219|(1:221)|222|(2:228|(16:234|(2:241|(2:242|(1:402)(2:244|(2:403|246)(1:404))))(0)|247|(0)(1:256)|257|(3:262|(1:264)|265)|266|(1:268)|269|(1:273)|274|(3:276|(7:278|(1:280)(1:281)|282|(1:284)|285|(4:289|(1:291)|292|(1:294))|295)(1:297)|296)(16:298|(11:300|(1:305)|332|(1:334)|335|388|336|337|338|343|(5:349|(1:351)(1:352)|(1:356)|(1:358)|359))(1:306)|307|(2:309|(2:315|316)(3:312|(1:314)(0)|316))(1:317)|(5:319|(1:321)(1:322)|323|(1:325)|326)(1:327)|328|(1:330)(1:331)|332|(0)|335|388|336|337|338|343|(7:345|347|349|(0)(0)|(2:354|356)|(0)|359)(0))|360|(3:362|(1:364)(1:365)|(5:367|(1:369)|370|(1:372)|373))|374|375)(1:233))(1:226)|227|257|(4:260|262|(0)|265)(0)|266|(0)|269|(2:271|273)|274|(0)(0)|360|(0)|374|375)(1:183)|187|(20:200|203|(0)(3:212|(3:215|(1:406)(1:407)|213)|405)|(0)|219|(0)|222|(3:224|228|(5:231|234|(4:237|239|241|(3:242|(0)(0)|404))(0)|247|(1:227)(1:227))(0))(0)|257|(0)(0)|266|(0)|269|(0)|274|(0)(0)|360|(0)|374|375)(1:201)|202|(0)|219|(0)|222|(0)(0)|257|(0)(0)|266|(0)|269|(0)|274|(0)(0)|360|(0)|374|375)(2:376|377))|121|(0)(0)|(0)(0)|(0)(0)|149|(0)(0))|(3:111|(1:113)(1:114)|115)|116|118|(0)(0)|121|(0)(0)|(0)(0)|(0)(0)|149|(0)(0))|35|390|39|(0)(0)|28|52|(2:54|63)(0)|64|(0)(0)|86|(0)|394|89|(0)(0)|93|(14:95|97|(0)(0)|101|(0)(0)|116|118|(0)(0)|121|(0)(0)|(0)(0)|(0)(0)|149|(0)(0))|(0)|116|118|(0)(0)|121|(0)(0)|(0)(0)|(0)(0)|149|(0)(0))|27|28|52|(0)(0)|64|(0)(0)|86|(0)|394|89|(0)(0)|93|(0)|(0)|116|118|(0)(0)|121|(0)(0)|(0)(0)|(0)(0)|149|(0)(0)) */
    /* JADX WARN: Can't wrap try/catch for region: R(30:29|(2:392|30)|31|(1:34)(27:36|(1:38)|390|39|(7:41|(1:43)(1:45)|386|46|396|47|48)|28|52|(1:63)(4:56|(1:58)(1:59)|60|(1:62)(0))|64|(2:66|(2:68|(2:70|(2:72|(2:74|(2:76|(1:78)(1:79))(1:80))(1:81))(1:82))(1:83))(1:84))(1:85)|86|(1:88)|394|89|(1:91)(1:92)|93|(13:97|(1:99)(1:100)|101|(2:106|107)(3:400|104|107)|116|118|(1:120)(7:122|(0)(1:125)|(3:398|127|(1:129)(1:130))(0)|(2:136|(1:138)(4:139|(3:142|(1:409)(1:410)|140)|408|145))(1:145)|(1:147)(1:148)|149|(30:151|(2:153|(1:155)(1:156))|157|(1:159)|160|(2:162|(1:164)(1:165))(0)|166|(2:168|(4:173|(1:175)|176|(1:178))(1:(5:172|173|(0)|176|(0))))(0)|179|(20:184|(1:186)|(1:218)|219|(1:221)|222|(2:228|(16:234|(2:241|(2:242|(1:402)(2:244|(2:403|246)(1:404))))(0)|247|(0)(1:256)|257|(3:262|(1:264)|265)|266|(1:268)|269|(1:273)|274|(3:276|(7:278|(1:280)(1:281)|282|(1:284)|285|(4:289|(1:291)|292|(1:294))|295)(1:297)|296)(16:298|(11:300|(1:305)|332|(1:334)|335|388|336|337|338|343|(5:349|(1:351)(1:352)|(1:356)|(1:358)|359))(1:306)|307|(2:309|(2:315|316)(3:312|(1:314)(0)|316))(1:317)|(5:319|(1:321)(1:322)|323|(1:325)|326)(1:327)|328|(1:330)(1:331)|332|(0)|335|388|336|337|338|343|(7:345|347|349|(0)(0)|(2:354|356)|(0)|359)(0))|360|(3:362|(1:364)(1:365)|(5:367|(1:369)|370|(1:372)|373))|374|375)(1:233))(1:226)|227|257|(4:260|262|(0)|265)(0)|266|(0)|269|(2:271|273)|274|(0)(0)|360|(0)|374|375)(1:183)|187|(20:200|203|(0)(3:212|(3:215|(1:406)(1:407)|213)|405)|(0)|219|(0)|222|(3:224|228|(5:231|234|(4:237|239|241|(3:242|(0)(0)|404))(0)|247|(1:227)(1:227))(0))(0)|257|(0)(0)|266|(0)|269|(0)|274|(0)(0)|360|(0)|374|375)(1:201)|202|(0)|219|(0)|222|(0)(0)|257|(0)(0)|266|(0)|269|(0)|274|(0)(0)|360|(0)|374|375)(2:376|377))|121|(0)(0)|(0)(0)|(0)(0)|149|(0)(0))|(3:111|(1:113)(1:114)|115)|116|118|(0)(0)|121|(0)(0)|(0)(0)|(0)(0)|149|(0)(0))|35|390|39|(0)(0)|28|52|(2:54|63)(0)|64|(0)(0)|86|(0)|394|89|(0)(0)|93|(14:95|97|(0)(0)|101|(0)(0)|116|118|(0)(0)|121|(0)(0)|(0)(0)|(0)(0)|149|(0)(0))|(0)|116|118|(0)(0)|121|(0)(0)|(0)(0)|(0)(0)|149|(0)(0)) */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x02e3, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:117:0x0302, code lost:
    
        com.google.android.gms.measurement.internal.Y.k(r15);
        r15.g.h("Fetching Google App Id failed with exception. appId", com.google.android.gms.measurement.internal.I.a0(r8), r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:339:0x0957, code lost:
    
        r2 = r22;
        r0 = r2.x;
     */
    /* JADX WARN: Code restructure failed: missing block: B:340:0x0963, code lost:
    
        if (android.text.TextUtils.isEmpty(r0.l()) == false) goto L341;
     */
    /* JADX WARN: Code restructure failed: missing block: B:341:0x0965, code lost:
    
        com.google.android.gms.measurement.internal.Y.k(r21);
        r6 = r21;
        r6.j.f("Remote config removed with active feature rollouts");
        r8 = null;
        r0.m(null);
     */
    /* JADX WARN: Code restructure failed: missing block: B:342:0x0976, code lost:
    
        r6 = r21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x01b7, code lost:
    
        r2 = r19;
     */
    /* JADX WARN: Removed duplicated region for block: B:100:0x02cb A[Catch: IllegalStateException -> 0x02e3, TryCatch #4 {IllegalStateException -> 0x02e3, blocks: (B:89:0x02a5, B:93:0x02b1, B:95:0x02ba, B:97:0x02c0, B:101:0x02cf, B:104:0x02da, B:107:0x02e0, B:100:0x02cb, B:111:0x02e7, B:113:0x02f8, B:115:0x02fd, B:114:0x02fb), top: B:394:0x02a5 }] */
    /* JADX WARN: Removed duplicated region for block: B:106:0x02df  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x02e7 A[Catch: IllegalStateException -> 0x02e3, TryCatch #4 {IllegalStateException -> 0x02e3, blocks: (B:89:0x02a5, B:93:0x02b1, B:95:0x02ba, B:97:0x02c0, B:101:0x02cf, B:104:0x02da, B:107:0x02e0, B:100:0x02cb, B:111:0x02e7, B:113:0x02f8, B:115:0x02fd, B:114:0x02fb), top: B:394:0x02a5 }] */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0325  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x0333  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x0354  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x036c  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x039b  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x039f  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x03a6  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x03c3  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x047c  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x0496  */
    /* JADX WARN: Removed duplicated region for block: B:175:0x04ae  */
    /* JADX WARN: Removed duplicated region for block: B:178:0x04ce  */
    /* JADX WARN: Removed duplicated region for block: B:218:0x05bc  */
    /* JADX WARN: Removed duplicated region for block: B:221:0x05e9  */
    /* JADX WARN: Removed duplicated region for block: B:224:0x05fd  */
    /* JADX WARN: Removed duplicated region for block: B:228:0x0621  */
    /* JADX WARN: Removed duplicated region for block: B:234:0x0645  */
    /* JADX WARN: Removed duplicated region for block: B:244:0x0675  */
    /* JADX WARN: Removed duplicated region for block: B:260:0x06ce  */
    /* JADX WARN: Removed duplicated region for block: B:262:0x06d4  */
    /* JADX WARN: Removed duplicated region for block: B:264:0x06f2  */
    /* JADX WARN: Removed duplicated region for block: B:268:0x0721  */
    /* JADX WARN: Removed duplicated region for block: B:271:0x073b  */
    /* JADX WARN: Removed duplicated region for block: B:276:0x0754  */
    /* JADX WARN: Removed duplicated region for block: B:298:0x07c2  */
    /* JADX WARN: Removed duplicated region for block: B:315:0x0836  */
    /* JADX WARN: Removed duplicated region for block: B:334:0x0932  */
    /* JADX WARN: Removed duplicated region for block: B:349:0x099d  */
    /* JADX WARN: Removed duplicated region for block: B:351:0x09a5  */
    /* JADX WARN: Removed duplicated region for block: B:352:0x09a8  */
    /* JADX WARN: Removed duplicated region for block: B:358:0x09bd  */
    /* JADX WARN: Removed duplicated region for block: B:362:0x09f2  */
    /* JADX WARN: Removed duplicated region for block: B:376:0x0a63  */
    /* JADX WARN: Removed duplicated region for block: B:398:0x0344 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:400:0x02da A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:402:0x0684 A[EDGE_INSN: B:402:0x0684->B:247:0x0684 BREAK  A[LOOP:0: B:242:0x066f->B:404:?], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x019a A[Catch: NameNotFoundException -> 0x01b7, TryCatch #2 {NameNotFoundException -> 0x01b7, blocks: (B:39:0x018f, B:41:0x019a, B:43:0x01a6), top: B:390:0x018f }] */
    /* JADX WARN: Removed duplicated region for block: B:54:0x01e7  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x0206  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0211  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x028b  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x029f  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x02af  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x02b0  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x02ba A[Catch: IllegalStateException -> 0x02e3, TryCatch #4 {IllegalStateException -> 0x02e3, blocks: (B:89:0x02a5, B:93:0x02b1, B:95:0x02ba, B:97:0x02c0, B:101:0x02cf, B:104:0x02da, B:107:0x02e0, B:100:0x02cb, B:111:0x02e7, B:113:0x02f8, B:115:0x02fd, B:114:0x02fb), top: B:394:0x02a5 }] */
    /* JADX WARN: Removed duplicated region for block: B:99:0x02ca  */
    /* JADX WARN: Type inference failed for: r2v29, types: [com.google.android.gms.measurement.internal.w0] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final void f() throws android.content.res.Resources.NotFoundException, android.content.pm.PackageManager.NameNotFoundException, java.lang.ClassNotFoundException {
        /*
            Method dump skipped, instructions count: 2683
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.common.util.concurrent.d.f():void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // java.lang.Runnable
    public final void run() throws JSONException, com.google.android.gms.internal.appset.d, InterruptedException, Resources.NotFoundException, PackageManager.NameNotFoundException, ClassNotFoundException {
        Throwable thA;
        InterfaceC1657g interfaceC1657g;
        e eVar = null;
        androidx.work.impl.model.q qVar = null;
        try {
            switch (this.a) {
                case 0:
                    e eVar2 = (e) this.b;
                    boolean z = eVar2 instanceof com.google.common.util.concurrent.internal.a;
                    c cVar = (c) this.c;
                    if (z && (thA = ((com.google.common.util.concurrent.internal.a) eVar2).a()) != null) {
                        cVar.onFailure(thA);
                        return;
                    }
                    try {
                        com.google.common.base.b.g("Future was expected to be done: %s", eVar2, eVar2.isDone());
                        Object[] objArr = false;
                        while (true) {
                            try {
                                Object obj = eVar2.get();
                                if (objArr != false) {
                                    Thread.currentThread().interrupt();
                                }
                                cVar.onSuccess(obj);
                                return;
                            } catch (InterruptedException unused) {
                                objArr = true;
                            } catch (Throwable th) {
                                if (objArr != false) {
                                    Thread.currentThread().interrupt();
                                }
                                throw th;
                            }
                        }
                    } catch (ExecutionException e) {
                        cVar.onFailure(e.getCause());
                        return;
                    } catch (Throwable th2) {
                        cVar.onFailure(th2);
                        return;
                    }
                    break;
                case 1:
                    try {
                        androidx.camera.core.impl.utils.futures.b bVar = (androidx.camera.core.impl.utils.futures.b) this.c;
                        Object objB = androidx.camera.core.impl.utils.futures.i.b((e) this.b);
                        androidx.concurrent.futures.i iVar = bVar.b;
                        if (iVar != null) {
                            iVar.b(objB);
                        }
                    } catch (CancellationException unused2) {
                        ((androidx.camera.core.impl.utils.futures.b) this.c).cancel(false);
                    } catch (ExecutionException e2) {
                        androidx.camera.core.impl.utils.futures.b bVar2 = (androidx.camera.core.impl.utils.futures.b) this.c;
                        Throwable cause = e2.getCause();
                        androidx.concurrent.futures.i iVar2 = bVar2.b;
                        if (iVar2 != null) {
                            iVar2.d(cause);
                        }
                    }
                    return;
                case 2:
                    ((C1017d) this.b).a = this.c;
                    return;
                case 3:
                    try {
                        Method method = AbstractC1018e.d;
                        Object obj2 = this.c;
                        Object obj3 = this.b;
                        if (method != null) {
                            method.invoke(obj3, obj2, Boolean.FALSE, "AppCompat recreation");
                        } else {
                            AbstractC1018e.e.invoke(obj3, obj2, Boolean.FALSE);
                        }
                        return;
                    } catch (RuntimeException e3) {
                        if (e3.getClass() == RuntimeException.class && e3.getMessage() != null && e3.getMessage().startsWith("Unable to stop")) {
                            throw e3;
                        }
                        return;
                    } catch (Throwable th3) {
                        Log.e("ActivityRecreator", "Exception while invoking performStopActivity", th3);
                        return;
                    }
                case 4:
                    ((androidx.camera.core.processing.d) this.b).accept(this.c);
                    return;
                case 5:
                    e eVar3 = (e) this.b;
                    boolean zIsCancelled = eVar3.isCancelled();
                    C5028l c5028l = (C5028l) this.c;
                    if (zIsCancelled) {
                        c5028l.b(null);
                        return;
                    }
                    try {
                        p pVar = r.b;
                        c5028l.resumeWith(G.b(eVar3));
                        return;
                    } catch (ExecutionException e4) {
                        p pVar2 = r.b;
                        Throwable cause2 = e4.getCause();
                        Intrinsics.d(cause2);
                        c5028l.resumeWith(Z.b(cause2));
                        return;
                    }
                case 6:
                    C1433e c1433e = ((androidx.work.impl.foreground.a) this.c).a.f;
                    String str = (String) this.b;
                    synchronized (c1433e.k) {
                        try {
                            F fC = c1433e.c(str);
                            if (fC != null) {
                                qVar = fC.a;
                            }
                        } finally {
                        }
                    }
                    if (qVar == null || !qVar.b()) {
                        return;
                    }
                    synchronized (((androidx.work.impl.foreground.a) this.c).c) {
                        ((androidx.work.impl.foreground.a) this.c).f.put(A2.a(qVar), qVar);
                        androidx.work.impl.foreground.a aVar = (androidx.work.impl.foreground.a) this.c;
                        ((androidx.work.impl.foreground.a) this.c).g.put(A2.a(qVar), androidx.work.impl.constraints.o.a(aVar.h, qVar, aVar.b.b, aVar));
                    }
                    return;
                case 7:
                    try {
                        ((Runnable) this.c).run();
                        synchronized (((ExecutorC0060p) this.b).d) {
                            ((ExecutorC0060p) this.b).a();
                        }
                        return;
                    } catch (Throwable th4) {
                        synchronized (((ExecutorC0060p) this.b).d) {
                            ((ExecutorC0060p) this.b).a();
                            throw th4;
                        }
                    }
                case 8:
                    Future future = (Future) this.b;
                    if (future.isDone() || future.isCancelled()) {
                        return;
                    }
                    future.cancel(true);
                    AbstractC3819n0.f("BillingClient", "Async task is taking too long, cancel it!");
                    Runnable runnable = (Runnable) this.c;
                    if (runnable != null) {
                        runnable.run();
                        return;
                    }
                    return;
                case 9:
                    C1473b c1473b = (C1473b) this.b;
                    com.android.billingclient.api.e eVar4 = (com.android.billingclient.api.e) this.c;
                    if (((k) c1473b.e.d) != null) {
                        ((k) c1473b.e.d).a(eVar4, null);
                        return;
                    } else {
                        AbstractC3819n0.f("BillingClient", "No valid listener is set in BroadcastManager");
                        return;
                    }
                case 10:
                    try {
                        ((com.android.volley.c) this.c).b.put((com.android.volley.l) this.b);
                        return;
                    } catch (InterruptedException unused3) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                case 11:
                    a();
                    return;
                case 12:
                    com.bumptech.glide.load.resource.bitmap.u uVarA = com.bumptech.glide.load.resource.bitmap.u.a();
                    uVarA.getClass();
                    com.bumptech.glide.util.m.a();
                    uVarA.d.set(true);
                    ((com.bumptech.glide.manager.d) this.c).b.b = true;
                    ((com.bumptech.glide.manager.d) this.c).a.getViewTreeObserver().removeOnDrawListener((com.bumptech.glide.manager.d) this.b);
                    ((com.bumptech.glide.manager.d) this.c).b.a.clear();
                    return;
                case 13:
                    AdManagerAdView.zza((AdManagerAdView) this.b, (AdManagerAdRequest) this.c);
                    return;
                case 14:
                    b();
                    return;
                case 15:
                    ((com.google.android.gms.ads.internal.overlay.d) ((com.google.android.gms.ads.internal.overlay.g) this.b).d).b.getWindow().setBackgroundDrawable((BitmapDrawable) this.c);
                    return;
                case 16:
                    j jVar = j.C;
                    androidx.camera.camera2.interop.c cVar2 = jVar.o;
                    C1633i c1633i = (C1633i) this.b;
                    Context context = c1633i.a;
                    if (cVar2.f(context, c1633i.d, c1633i.e)) {
                        ((C2227jd) this.c).execute(new RunnableC1626b(c1633i, 3));
                        return;
                    } else {
                        jVar.o.b(context, c1633i.d, c1633i.e);
                        return;
                    }
                case 17:
                    j.C.k.getClass();
                    l1.J((Hk) this.b, "cld_r", SystemClock.elapsedRealtime() - ((Long) this.c).longValue());
                    return;
                case 18:
                    c();
                    return;
                case 19:
                    ((C1635a) ((s) this.b).c).b.evaluateJavascript((String) this.c, null);
                    return;
                case 20:
                    d();
                    return;
                case 21:
                    p0 p0Var = (p0) this.c;
                    com.google.android.gms.common.api.internal.n nVar = (com.google.android.gms.common.api.internal.n) ((C1647e) p0Var.f).j.get((C1643a) p0Var.d);
                    if (nVar == null) {
                        return;
                    }
                    ConnectionResult connectionResult = (ConnectionResult) this.b;
                    if (!(connectionResult.b == 0)) {
                        nVar.k(connectionResult, null);
                        return;
                    }
                    p0Var.b = true;
                    com.google.android.gms.common.api.c cVar3 = (com.google.android.gms.common.api.c) p0Var.c;
                    if (cVar3.b()) {
                        if (!p0Var.b || (interfaceC1657g = (InterfaceC1657g) p0Var.a) == null) {
                            return;
                        }
                        ((AbstractC1655e) cVar3).k(interfaceC1657g, (Set) p0Var.e);
                        return;
                    }
                    try {
                        AbstractC1656f abstractC1656f = (AbstractC1656f) cVar3;
                        ((AbstractC1655e) cVar3).k(null, abstractC1656f.b() ? abstractC1656f.z : Collections.EMPTY_SET);
                        return;
                    } catch (SecurityException e5) {
                        Log.e("GoogleApiManager", "Failed to get service from broker. ", e5);
                        ((AbstractC1655e) cVar3).f("Failed to get service from broker.");
                        nVar.k(new ConnectionResult(10), null);
                        return;
                    }
                case EventType.WINDOW_STATE /* 22 */:
                    e();
                    return;
                case EventType.AUDIO /* 23 */:
                    com.google.android.gms.internal.appset.e eVar5 = (com.google.android.gms.internal.appset.e) this.b;
                    Context context2 = (Context) eVar5.b;
                    String string = com.google.android.gms.internal.appset.e.y(context2).getString("app_set_id", null);
                    long j = com.google.android.gms.internal.appset.e.y((Context) eVar5.b).getLong("app_set_id_last_used_time", -1L);
                    long j2 = j != -1 ? 33696000000L + j : -1L;
                    com.google.android.gms.tasks.f fVar = (com.google.android.gms.tasks.f) this.c;
                    if (string == null || System.currentTimeMillis() > j2) {
                        string = UUID.randomUUID().toString();
                        try {
                            if (!context2.getSharedPreferences("app_set_id_storage", 0).edit().putString("app_set_id", string).commit()) {
                                String strValueOf = String.valueOf(context2.getPackageName());
                                Log.e("AppSet", strValueOf.length() != 0 ? "Failed to store app set ID generated for App ".concat(strValueOf) : new String("Failed to store app set ID generated for App "));
                                throw new com.google.android.gms.internal.appset.d("Failed to store the app set ID.");
                            }
                            com.google.android.gms.internal.appset.e.z(context2);
                            if (!context2.getSharedPreferences("app_set_id_storage", 0).edit().putLong("app_set_id_creation_time", System.currentTimeMillis()).commit()) {
                                String strValueOf2 = String.valueOf(context2.getPackageName());
                                Log.e("AppSet", strValueOf2.length() != 0 ? "Failed to store app set ID creation time for App ".concat(strValueOf2) : new String("Failed to store app set ID creation time for App "));
                                throw new com.google.android.gms.internal.appset.d("Failed to store the app set ID creation time.");
                            }
                        } catch (com.google.android.gms.internal.appset.d e6) {
                            fVar.a(e6);
                            return;
                        }
                    } else {
                        try {
                            com.google.android.gms.internal.appset.e.z(context2);
                        } catch (com.google.android.gms.internal.appset.d e7) {
                            fVar.a(e7);
                            return;
                        }
                    }
                    fVar.b(new com.google.android.gms.appset.b(string, 1));
                    return;
                case EventType.VIDEO /* 24 */:
                    InterfaceC3873i0 interfaceC3873i0 = (InterfaceC3873i0) this.b;
                    interfaceC3873i0.b();
                    if (com.google.android.material.shape.e.x()) {
                        interfaceC3873i0.i().c0(this);
                        return;
                    }
                    AbstractC3876k abstractC3876k = (AbstractC3876k) this.c;
                    z = abstractC3876k.c != 0;
                    abstractC3876k.c = 0L;
                    if (z) {
                        abstractC3876k.b();
                        return;
                    }
                    return;
                case EventType.SUBS /* 25 */:
                    f();
                    return;
                case EventType.CDN /* 26 */:
                    BinderC3869g0 binderC3869g0 = (BinderC3869g0) this.c;
                    binderC3869g0.a.j();
                    zzai zzaiVar = (zzai) this.b;
                    Object objA = zzaiVar.c.a();
                    r1 r1Var = binderC3869g0.a;
                    if (objA == null) {
                        r1Var.getClass();
                        String str2 = zzaiVar.a;
                        u.h(str2);
                        zzr zzrVarZ = r1Var.z(str2);
                        if (zzrVarZ != null) {
                            r1Var.P(zzaiVar, zzrVarZ);
                            return;
                        }
                        return;
                    }
                    r1Var.getClass();
                    String str3 = zzaiVar.a;
                    u.h(str3);
                    zzr zzrVarZ2 = r1Var.z(str3);
                    if (zzrVarZ2 != null) {
                        r1Var.U(zzaiVar, zzrVarZ2);
                        return;
                    }
                    return;
                case 27:
                    Y y = (Y) ((D0) this.b).b;
                    A aN = y.n();
                    String str4 = aN.s;
                    String str5 = (String) this.c;
                    if (str4 != null && !str4.equals(str5)) {
                        z = true;
                    }
                    aN.s = str5;
                    if (z) {
                        y.n().Z();
                        return;
                    }
                    return;
                case 28:
                    D0 d0 = (D0) this.b;
                    d0.S();
                    if (Build.VERSION.SDK_INT < 30) {
                        return;
                    }
                    O o = ((Y) d0.b).h;
                    Y.h(o);
                    SparseArray sparseArrayY = o.Y();
                    for (zzov zzovVar : (List) this.c) {
                        int i = zzovVar.c;
                        if (!sparseArrayY.contains(i) || ((Long) sparseArrayY.get(i)).longValue() < zzovVar.b) {
                            d0.r0().add(zzovVar);
                        }
                    }
                    d0.f0();
                    return;
                default:
                    D0 d02 = (D0) this.c;
                    d02.S();
                    d02.Q();
                    Bundle bundle = (Bundle) this.b;
                    String string2 = bundle.getString("name");
                    u.e(string2);
                    Y y2 = (Y) d02.b;
                    if (!y2.a()) {
                        I i2 = y2.i;
                        Y.k(i2);
                        i2.o.f("Conditional property not cleared since app measurement is disabled");
                        return;
                    } else {
                        zzqb zzqbVar = new zzqb(0L, null, string2, "");
                        try {
                            x1 x1Var = y2.l;
                            Y.h(x1Var);
                            bundle.getString("app_id");
                            y2.r().Z(new zzai(bundle.getString("app_id"), "", zzqbVar, bundle.getLong("creation_timestamp"), bundle.getBoolean("active"), bundle.getString("trigger_event_name"), null, bundle.getLong("trigger_timeout"), null, bundle.getLong("time_to_live"), x1Var.X(bundle.getString("expired_event_name"), bundle.getBundle("expired_event_params"), "", bundle.getLong("creation_timestamp"), true)));
                            return;
                        } catch (IllegalArgumentException unused4) {
                            return;
                        }
                    }
            }
        } finally {
            ((androidx.camera.core.impl.utils.futures.b) this.c).g = null;
        }
        ((androidx.camera.core.impl.utils.futures.b) this.c).g = null;
    }

    public String toString() {
        switch (this.a) {
            case 0:
                com.quizlet.data.repository.set.f fVar = new com.quizlet.data.repository.set.f(d.class.getSimpleName(), 8);
                com.quizlet.data.repository.login.a aVar = new com.quizlet.data.repository.login.a();
                ((com.quizlet.data.repository.login.a) fVar.d).c = aVar;
                fVar.d = aVar;
                aVar.b = (c) this.c;
                return fVar.toString();
            default:
                return super.toString();
        }
    }

    public /* synthetic */ d(l1 l1Var, Hk hk, Long l) {
        this.a = 17;
        this.b = hk;
        this.c = l;
    }

    public /* synthetic */ d(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    public d(e futureToObserve, C5028l continuation) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(futureToObserve, "futureToObserve");
        Intrinsics.checkNotNullParameter(continuation, "continuation");
        this.b = futureToObserve;
        this.c = continuation;
    }
}
