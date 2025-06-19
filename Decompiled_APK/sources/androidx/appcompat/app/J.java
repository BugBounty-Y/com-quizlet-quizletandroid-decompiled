package androidx.appcompat.app;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteException;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Handler;
import android.os.Looper;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.Log;
import android.view.Menu;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.AnimationUtils;
import android.widget.ListView;
import androidx.appcompat.widget.C0113u0;
import androidx.appcompat.widget.Toolbar;
import androidx.compose.ui.platform.C0971v;
import androidx.core.view.V;
import androidx.viewpager.widget.ViewPager;
import com.android.billingclient.api.C1473b;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.H0;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.ads.internal.client.J0;
import com.google.android.gms.ads.internal.client.K0;
import com.google.android.gms.common.internal.AbstractC1655e;
import com.google.android.gms.internal.ads.InterfaceC2741vc;
import com.google.android.gms.internal.ads.K9;
import com.google.android.gms.internal.ads.N5;
import com.google.android.gms.internal.ads.P7;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.lang.ref.ReferenceQueue;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import kotlin.Unit;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class J implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ J(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void b() {
        com.google.android.gms.ads.internal.util.C c = (com.google.android.gms.ads.internal.util.C) this.b;
        if (c.b) {
            if (!(c.i() && c.j()) && ((Boolean) P7.b.o()).booleanValue()) {
                synchronized (c.a) {
                    try {
                        if (Looper.getMainLooper() == null) {
                            return;
                        }
                        if (c.e == null) {
                            c.e = new N5();
                        }
                        N5 n5 = c.e;
                        synchronized (n5.c) {
                            try {
                                if (n5.a) {
                                    com.google.android.gms.ads.internal.util.client.i.d("Content hash thread already started, quitting...");
                                } else {
                                    n5.a = true;
                                    n5.start();
                                }
                            } finally {
                            }
                        }
                        com.google.android.gms.ads.internal.util.client.i.g("start fetching content...");
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
        }
    }

    public kotlin.collections.builders.p a() throws IOException {
        androidx.room.n nVar = (androidx.room.n) this.b;
        kotlin.collections.builders.p pVar = new kotlin.collections.builders.p();
        Cursor cursorM = nVar.a.m(new androidx.sqlite.db.a("SELECT * FROM room_table_modification_log WHERE invalidated = 1;", 0));
        while (cursorM.moveToNext()) {
            try {
                pVar.add(Integer.valueOf(cursorM.getInt(0)));
            } finally {
            }
        }
        Unit unit = Unit.a;
        cursorM.close();
        kotlin.collections.builders.p pVarA = Z.a(pVar);
        if (pVarA.a.isEmpty()) {
            return pVarA;
        }
        if (((androidx.room.n) this.b).h == null) {
            throw new IllegalStateException("Required value was null.");
        }
        androidx.sqlite.db.framework.i iVar = ((androidx.room.n) this.b).h;
        if (iVar == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        iVar.a();
        return pVarA;
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0041, code lost:
    
        if (r1 == false) goto L47;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x004a, code lost:
    
        r1 = r1 | java.lang.Thread.interrupted();
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x004b, code lost:
    
        r4.run();
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0051, code lost:
    
        r2 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0052, code lost:
    
        com.google.android.gms.internal.measurement.AbstractC3053s1.d("SequentialExecutor", "Exception while executing runnable " + r4, r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:?, code lost:
    
        return;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:?, code lost:
    
        return;
     */
    /* JADX WARN: Removed duplicated region for block: B:42:0x003a A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void c() {
        /*
            r10 = this;
            r0 = 0
            r1 = r0
        L2:
            java.lang.Object r2 = r10.b     // Catch: java.lang.Throwable -> L4f
            androidx.camera.core.impl.utils.executor.k r2 = (androidx.camera.core.impl.utils.executor.k) r2     // Catch: java.lang.Throwable -> L4f
            java.util.ArrayDeque r2 = r2.a     // Catch: java.lang.Throwable -> L4f
            monitor-enter(r2)     // Catch: java.lang.Throwable -> L4f
            r3 = 1
            if (r0 != 0) goto L2c
            java.lang.Object r0 = r10.b     // Catch: java.lang.Throwable -> L20
            androidx.camera.core.impl.utils.executor.k r0 = (androidx.camera.core.impl.utils.executor.k) r0     // Catch: java.lang.Throwable -> L20
            int r4 = r0.d     // Catch: java.lang.Throwable -> L20
            r5 = 4
            if (r4 != r5) goto L22
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L20
            if (r1 == 0) goto L44
        L18:
            java.lang.Thread r0 = java.lang.Thread.currentThread()
            r0.interrupt()
            goto L44
        L20:
            r0 = move-exception
            goto L69
        L22:
            long r6 = r0.e     // Catch: java.lang.Throwable -> L20
            r8 = 1
            long r6 = r6 + r8
            r0.e = r6     // Catch: java.lang.Throwable -> L20
            r0.d = r5     // Catch: java.lang.Throwable -> L20
            r0 = r3
        L2c:
            java.lang.Object r4 = r10.b     // Catch: java.lang.Throwable -> L20
            androidx.camera.core.impl.utils.executor.k r4 = (androidx.camera.core.impl.utils.executor.k) r4     // Catch: java.lang.Throwable -> L20
            java.util.ArrayDeque r4 = r4.a     // Catch: java.lang.Throwable -> L20
            java.lang.Object r4 = r4.poll()     // Catch: java.lang.Throwable -> L20
            java.lang.Runnable r4 = (java.lang.Runnable) r4     // Catch: java.lang.Throwable -> L20
            if (r4 != 0) goto L45
            java.lang.Object r0 = r10.b     // Catch: java.lang.Throwable -> L20
            androidx.camera.core.impl.utils.executor.k r0 = (androidx.camera.core.impl.utils.executor.k) r0     // Catch: java.lang.Throwable -> L20
            r0.d = r3     // Catch: java.lang.Throwable -> L20
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L20
            if (r1 == 0) goto L44
            goto L18
        L44:
            return
        L45:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L20
            boolean r2 = java.lang.Thread.interrupted()     // Catch: java.lang.Throwable -> L4f
            r1 = r1 | r2
            r4.run()     // Catch: java.lang.Throwable -> L4f java.lang.RuntimeException -> L51
            goto L2
        L4f:
            r0 = move-exception
            goto L6b
        L51:
            r2 = move-exception
            java.lang.String r3 = "SequentialExecutor"
            java.lang.StringBuilder r5 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L4f
            r5.<init>()     // Catch: java.lang.Throwable -> L4f
            java.lang.String r6 = "Exception while executing runnable "
            r5.append(r6)     // Catch: java.lang.Throwable -> L4f
            r5.append(r4)     // Catch: java.lang.Throwable -> L4f
            java.lang.String r4 = r5.toString()     // Catch: java.lang.Throwable -> L4f
            com.google.android.gms.internal.measurement.AbstractC3053s1.d(r3, r4, r2)     // Catch: java.lang.Throwable -> L4f
            goto L2
        L69:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L20
            throw r0     // Catch: java.lang.Throwable -> L4f
        L6b:
            if (r1 == 0) goto L74
            java.lang.Thread r1 = java.lang.Thread.currentThread()
            r1.interrupt()
        L74:
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.J.c():void");
    }

    /* JADX INFO: Infinite loop detected, blocks: 8, insns: 0 */
    @Override // java.lang.Runnable
    public final void run() {
        Set setA;
        NetworkInfo activeNetworkInfo;
        switch (this.a) {
            case 0:
                M m = (M) this.b;
                w wVar = m.b;
                Menu menuF = m.F();
                androidx.appcompat.view.menu.n nVar = menuF instanceof androidx.appcompat.view.menu.n ? (androidx.appcompat.view.menu.n) menuF : null;
                if (nVar != null) {
                    nVar.w();
                }
                try {
                    menuF.clear();
                    if (!wVar.onCreatePanelMenu(0, menuF) || !wVar.onPreparePanel(0, null, menuF)) {
                        menuF.clear();
                    }
                    if (nVar != null) {
                        nVar.v();
                        return;
                    }
                    return;
                } finally {
                    if (nVar != null) {
                        nVar.v();
                    }
                }
            case 1:
                C0113u0 c0113u0 = (C0113u0) this.b;
                c0113u0.l = null;
                c0113u0.drawableStateChanged();
                return;
            case 2:
                ((Toolbar) this.b).v();
                return;
            case 3:
                com.quizlet.data.repository.login.a aVar = (com.quizlet.data.repository.login.a) this.b;
                if (((androidx.camera.core.impl.utils.executor.d) aVar.c).a.getAndSet(null) != null) {
                    ((Handler) aVar.a).removeCallbacks((androidx.camera.core.impl.utils.executor.d) aVar.c);
                    return;
                }
                return;
            case 4:
                try {
                    c();
                    return;
                } catch (Error e) {
                    synchronized (((androidx.camera.core.impl.utils.executor.k) this.b).a) {
                        ((androidx.camera.core.impl.utils.executor.k) this.b).d = 1;
                        throw e;
                    }
                }
            case 5:
                ((com.google.common.util.concurrent.e) this.b).cancel(true);
                return;
            case 6:
                androidx.camera.core.impl.utils.futures.l lVar = (androidx.camera.core.impl.utils.futures.l) this.b;
                lVar.b = null;
                lVar.a = null;
                return;
            case 7:
                C0971v c0971v = (C0971v) this.b;
                c0971v.removeCallbacks(this);
                MotionEvent motionEvent = c0971v.x1;
                if (motionEvent != null) {
                    boolean z = motionEvent.getToolType(0) == 3;
                    int actionMasked = motionEvent.getActionMasked();
                    if (z) {
                        if (actionMasked == 10 || actionMasked == 1) {
                            return;
                        }
                    } else if (actionMasked == 1) {
                        return;
                    }
                    int i = 7;
                    if (actionMasked != 7 && actionMasked != 9) {
                        i = 2;
                    }
                    C0971v c0971v2 = (C0971v) this.b;
                    c0971v2.E(motionEvent, i, c0971v2.y1, false);
                    return;
                }
                return;
            case 8:
                ((View) this.b).setNestedScrollingEnabled(true);
                return;
            case 9:
                ((androidx.constraintlayout.motion.widget.r) this.b).z1.a();
                return;
            case 10:
                androidx.core.widget.f fVar = (androidx.core.widget.f) this.b;
                if (fVar.o) {
                    boolean z2 = fVar.m;
                    androidx.core.widget.a aVar2 = fVar.a;
                    if (z2) {
                        fVar.m = false;
                        long jCurrentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
                        aVar2.e = jCurrentAnimationTimeMillis;
                        aVar2.g = -1L;
                        aVar2.f = jCurrentAnimationTimeMillis;
                        aVar2.h = 0.5f;
                    }
                    if ((aVar2.g > 0 && AnimationUtils.currentAnimationTimeMillis() > aVar2.g + aVar2.i) || !fVar.e()) {
                        fVar.o = false;
                        return;
                    }
                    boolean z3 = fVar.n;
                    ListView listView = fVar.c;
                    if (z3) {
                        fVar.n = false;
                        long jUptimeMillis = SystemClock.uptimeMillis();
                        MotionEvent motionEventObtain = MotionEvent.obtain(jUptimeMillis, jUptimeMillis, 3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0);
                        listView.onTouchEvent(motionEventObtain);
                        motionEventObtain.recycle();
                    }
                    if (aVar2.f == 0) {
                        throw new RuntimeException("Cannot compute scroll delta before calling start()");
                    }
                    long jCurrentAnimationTimeMillis2 = AnimationUtils.currentAnimationTimeMillis();
                    float fA = aVar2.a(jCurrentAnimationTimeMillis2);
                    long j = jCurrentAnimationTimeMillis2 - aVar2.f;
                    aVar2.f = jCurrentAnimationTimeMillis2;
                    fVar.q.scrollListBy((int) (j * ((fA * 4.0f) + ((-4.0f) * fA * fA)) * aVar2.d));
                    WeakHashMap weakHashMap = V.a;
                    listView.postOnAnimation(this);
                    return;
                }
                return;
            case 11:
                ((androidx.customview.widget.d) this.b).n(0);
                return;
            case 12:
                ReentrantReadWriteLock.ReadLock lock = ((androidx.room.n) this.b).a.i.readLock();
                Intrinsics.checkNotNullExpressionValue(lock, "readWriteLock.readLock()");
                lock.lock();
                try {
                    try {
                    } finally {
                        lock.unlock();
                        ((androidx.room.n) this.b).getClass();
                    }
                } catch (SQLiteException e2) {
                    Log.e("ROOM", "Cannot run invalidation tracker. Is the db closed?", e2);
                    setA = kotlin.collections.M.a;
                } catch (IllegalStateException e3) {
                    Log.e("ROOM", "Cannot run invalidation tracker. Is the db closed?", e3);
                    setA = kotlin.collections.M.a;
                }
                if (((androidx.room.n) this.b).b() && ((androidx.room.n) this.b).f.compareAndSet(true, false) && !((androidx.room.n) this.b).a.h().I().p()) {
                    androidx.sqlite.db.framework.b bVarI = ((androidx.room.n) this.b).a.h().I();
                    bVarI.d();
                    try {
                        setA = a();
                        bVarI.B();
                        if (setA.isEmpty()) {
                            return;
                        }
                        androidx.room.n nVar2 = (androidx.room.n) this.b;
                        synchronized (nVar2.k) {
                            try {
                                Iterator it2 = nVar2.k.iterator();
                                while (true) {
                                    androidx.arch.core.internal.b bVar = (androidx.arch.core.internal.b) it2;
                                    if (bVar.hasNext()) {
                                        ((androidx.room.l) ((Map.Entry) bVar.next()).getValue()).a(setA);
                                    } else {
                                        Unit unit = Unit.a;
                                    }
                                }
                            } finally {
                            }
                        }
                        return;
                    } finally {
                        bVarI.i();
                    }
                }
                return;
            case 13:
                ViewPager viewPager = (ViewPager) this.b;
                viewPager.setScrollState(0);
                viewPager.q();
                return;
            case 14:
                com.android.billingclient.api.q qVar = (com.android.billingclient.api.q) this.b;
                C1473b c1473b = qVar.b;
                c1473b.p(0);
                com.android.billingclient.api.e eVar = com.android.billingclient.api.A.l;
                c1473b.x(24, 6, eVar);
                qVar.a(eVar);
                return;
            case 15:
                com.bumptech.glide.m mVar = (com.bumptech.glide.m) this.b;
                mVar.c.a(mVar);
                return;
            case 16:
                com.quizlet.data.interactor.progress.c cVar = (com.quizlet.data.interactor.progress.c) this.b;
                cVar.getClass();
                while (true) {
                    try {
                        cVar.e((com.bumptech.glide.load.engine.a) ((ReferenceQueue) cVar.c).remove());
                    } catch (InterruptedException unused) {
                        Thread.currentThread().interrupt();
                    }
                }
            case 17:
                synchronized (((com.google.ads.conversiontracking.l) this.b).a) {
                    try {
                        com.google.ads.conversiontracking.l lVar2 = (com.google.ads.conversiontracking.l) this.b;
                        if (lVar2.e) {
                            Context context = lVar2.c;
                            HashMap map = com.google.ads.conversiontracking.r.a;
                            ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
                            if (connectivityManager == null || ((activeNetworkInfo = connectivityManager.getActiveNetworkInfo()) != null && activeNetworkInfo.isConnected())) {
                                com.google.ads.conversiontracking.l lVar3 = (com.google.ads.conversiontracking.l) this.b;
                                if (!lVar3.d) {
                                    lVar3.b.addAll(lVar3.f.c());
                                    SharedPreferences.Editor editorEdit = ((com.google.ads.conversiontracking.l) this.b).c.getSharedPreferences("google_conversion", 0).edit();
                                    editorEdit.putLong("last_retry_time", System.currentTimeMillis());
                                    editorEdit.commit();
                                    com.google.ads.conversiontracking.l lVar4 = (com.google.ads.conversiontracking.l) this.b;
                                    lVar4.d = true;
                                    lVar4.a.notify();
                                    return;
                                }
                            }
                        }
                        return;
                    } finally {
                    }
                }
            case 18:
                InterfaceC1622x interfaceC1622x = ((H0) this.b).a.a;
                if (interfaceC1622x != null) {
                    try {
                        interfaceC1622x.u(1);
                        return;
                    } catch (RemoteException e4) {
                        com.google.android.gms.ads.internal.util.client.i.i("Could not notify onAdFailedToLoad event.", e4);
                        return;
                    }
                }
                return;
            case 19:
                InterfaceC1622x interfaceC1622x2 = ((J0) this.b).a;
                if (interfaceC1622x2 != null) {
                    try {
                        interfaceC1622x2.u(1);
                        return;
                    } catch (RemoteException e5) {
                        com.google.android.gms.ads.internal.util.client.i.i("Could not notify onAdFailedToLoad event.", e5);
                        return;
                    }
                }
                return;
            case 20:
                K9 k9 = ((K0) this.b).a;
                if (k9 != null) {
                    try {
                        k9.S2(Collections.EMPTY_LIST);
                        return;
                    } catch (RemoteException e6) {
                        com.google.android.gms.ads.internal.util.client.i.i("Could not notify onComplete event.", e6);
                        return;
                    }
                }
                return;
            case 21:
                InterfaceC2741vc interfaceC2741vc = (InterfaceC2741vc) this.b;
                if (interfaceC2741vc != null) {
                    try {
                        interfaceC2741vc.u(1);
                        return;
                    } catch (RemoteException e7) {
                        com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e7);
                        return;
                    }
                }
                return;
            case EventType.WINDOW_STATE /* 22 */:
                com.google.android.gms.ads.internal.overlay.b bVar2 = (com.google.android.gms.ads.internal.overlay.b) this.b;
                if (bVar2.h) {
                    bVar2.c.finish();
                    return;
                }
                return;
            case EventType.AUDIO /* 23 */:
                ((com.google.android.gms.ads.internal.overlay.d) this.b).q();
                return;
            case EventType.VIDEO /* 24 */:
                Thread.currentThread();
                androidx.compose.animation.core.J0 j0 = (androidx.compose.animation.core.J0) this.b;
                j0.getClass();
                j0.Q();
                return;
            case EventType.SUBS /* 25 */:
                b();
                return;
            case EventType.CDN /* 26 */:
                BroadcastReceiver.PendingResult pendingResult = (BroadcastReceiver.PendingResult) this.b;
                if (pendingResult != null) {
                    pendingResult.finish();
                    return;
                }
                return;
            case 27:
                if (((com.google.android.gms.tasks.f) this.b).c(new IOException("TIMEOUT"))) {
                    Log.w("Rpc", "No response");
                    return;
                }
                return;
            case 28:
                ((com.google.android.gms.common.api.internal.n) this.b).a();
                return;
            default:
                com.google.android.gms.common.api.internal.n nVar3 = (com.google.android.gms.common.api.internal.n) ((com.airbnb.lottie.network.c) this.b).b;
                ((AbstractC1655e) nVar3.b).f(nVar3.b.getClass().getName().concat(" disconnecting because it was signed out."));
                return;
        }
    }
}
