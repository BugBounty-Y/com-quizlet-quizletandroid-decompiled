package androidx.camera.camera2.internal;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.SystemClock;
import android.view.Surface;
import android.view.View;
import androidx.camera.core.C0187j;
import androidx.camera.core.C0194q;
import androidx.camera.core.C0196t;
import androidx.camera.core.RunnableC0193p;
import androidx.camera.core.impl.DeferrableSurface$SurfaceClosedException;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import androidx.work.EnumC1440n;
import androidx.work.rxjava3.RxWorker;
import com.braze.ui.inappmessage.DefaultInAppMessageViewWrapper;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.FirebaseCommonRegistrar;
import com.google.firebase.messaging.AbstractServiceC3969f;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigFetchThrottledException;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.camera.camera2.internal.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0143u implements androidx.camera.core.impl.utils.futures.a, androidx.concurrent.futures.j, androidx.camera.core.impl.Q, androidx.camera.core.i0, InterfaceC1062t, com.facebook.appevents.internal.k, com.google.android.datatransport.runtime.synchronization.a, com.google.android.datatransport.runtime.scheduling.persistence.e, com.google.firebase.inject.a, OnCompleteListener, com.google.android.gms.tasks.a, com.google.firebase.components.d, com.google.android.gms.tasks.e {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C0143u(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    private final Object k(Task task) {
        com.google.firebase.remoteconfig.internal.e eVar = (com.google.firebase.remoteconfig.internal.e) this.b;
        Date date = (Date) this.c;
        eVar.getClass();
        if (task.l()) {
            com.google.firebase.remoteconfig.internal.j jVar = eVar.g;
            synchronized (jVar.b) {
                jVar.a.edit().putInt("last_fetch_status", -1).putLong("last_fetch_time_in_millis", date.getTime()).apply();
            }
            return task;
        }
        Exception excG = task.g();
        if (excG == null) {
            return task;
        }
        if (excG instanceof FirebaseRemoteConfigFetchThrottledException) {
            com.google.firebase.remoteconfig.internal.j jVar2 = eVar.g;
            synchronized (jVar2.b) {
                jVar2.a.edit().putInt("last_fetch_status", 2).apply();
            }
            return task;
        }
        com.google.firebase.remoteconfig.internal.j jVar3 = eVar.g;
        synchronized (jVar3.b) {
            jVar3.a.edit().putInt("last_fetch_status", 1).apply();
        }
        return task;
    }

    @Override // com.google.android.datatransport.runtime.synchronization.a
    public Object a() {
        switch (this.a) {
            case 19:
                com.google.android.datatransport.runtime.scheduling.persistence.g gVar = (com.google.android.datatransport.runtime.scheduling.persistence.g) ((com.google.android.datatransport.runtime.scheduling.jobscheduling.i) this.b).c;
                gVar.getClass();
                Iterable iterable = (Iterable) this.c;
                if (iterable.iterator().hasNext()) {
                    gVar.a().compileStatement("DELETE FROM events WHERE _id in " + com.google.android.datatransport.runtime.scheduling.persistence.g.p(iterable)).execute();
                    break;
                }
                break;
            default:
                com.google.android.datatransport.runtime.scheduling.jobscheduling.i iVar = (com.google.android.datatransport.runtime.scheduling.jobscheduling.i) this.b;
                iVar.getClass();
                Iterator it2 = ((HashMap) this.c).entrySet().iterator();
                while (it2.hasNext()) {
                    ((com.google.android.datatransport.runtime.scheduling.persistence.g) iVar.i).j(((Integer) r2.getValue()).intValue(), com.google.android.datatransport.runtime.firebase.transport.c.INVALID_PAYLOD, (String) ((Map.Entry) it2.next()).getKey());
                }
                break;
        }
        return null;
    }

    @Override // com.google.android.datatransport.runtime.scheduling.persistence.e, io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        SQLiteDatabase sQLiteDatabase = (SQLiteDatabase) obj;
        com.google.android.datatransport.runtime.scheduling.persistence.g gVar = (com.google.android.datatransport.runtime.scheduling.persistence.g) this.b;
        com.google.android.datatransport.runtime.scheduling.persistence.a aVar = gVar.d;
        int i = aVar.b;
        com.google.android.datatransport.runtime.i iVar = (com.google.android.datatransport.runtime.i) this.c;
        ArrayList arrayListI = gVar.i(sQLiteDatabase, iVar, i);
        for (com.google.android.datatransport.d dVar : com.google.android.datatransport.d.values()) {
            if (dVar != iVar.c) {
                int size = aVar.b - arrayListI.size();
                if (size <= 0) {
                    break;
                }
                arrayListI.addAll(gVar.i(sQLiteDatabase, iVar.b(dVar), size));
            }
        }
        HashMap map = new HashMap();
        StringBuilder sb = new StringBuilder("event_id IN (");
        for (int i2 = 0; i2 < arrayListI.size(); i2++) {
            sb.append(((com.google.android.datatransport.runtime.scheduling.persistence.b) arrayListI.get(i2)).a);
            if (i2 < arrayListI.size() - 1) {
                sb.append(',');
            }
        }
        sb.append(')');
        Cursor cursorQuery = sQLiteDatabase.query("event_metadata", new String[]{"event_id", "name", "value"}, sb.toString(), null, null, null, null);
        while (cursorQuery.moveToNext()) {
            try {
                long j = cursorQuery.getLong(0);
                Set hashSet = (Set) map.get(Long.valueOf(j));
                if (hashSet == null) {
                    hashSet = new HashSet();
                    map.put(Long.valueOf(j), hashSet);
                }
                hashSet.add(new com.google.android.datatransport.runtime.scheduling.persistence.f(cursorQuery.getString(1), cursorQuery.getString(2)));
            } catch (Throwable th) {
                cursorQuery.close();
                throw th;
            }
        }
        cursorQuery.close();
        ListIterator listIterator = arrayListI.listIterator();
        while (listIterator.hasNext()) {
            com.google.android.datatransport.runtime.scheduling.persistence.b bVar = (com.google.android.datatransport.runtime.scheduling.persistence.b) listIterator.next();
            if (map.containsKey(Long.valueOf(bVar.a))) {
                androidx.compose.runtime.internal.j jVarC = bVar.c.c();
                long j2 = bVar.a;
                for (com.google.android.datatransport.runtime.scheduling.persistence.f fVar : (Set) map.get(Long.valueOf(j2))) {
                    jVarC.a(fVar.a, fVar.b);
                }
                listIterator.set(new com.google.android.datatransport.runtime.scheduling.persistence.b(j2, bVar.b, jVarC.b()));
            }
        }
        return arrayListI;
    }

    @Override // androidx.camera.core.i0
    public void b(C0187j c0187j) {
        androidx.camera.core.processing.c cVar = (androidx.camera.core.processing.c) this.b;
        cVar.getClass();
        androidx.camera.core.processing.util.f fVar = androidx.camera.core.processing.util.f.b;
        if (((androidx.camera.core.j0) this.c).c.a() && c0187j.d) {
            fVar = androidx.camera.core.processing.util.f.c;
        }
        androidx.camera.core.processing.e eVar = cVar.a;
        androidx.camera.core.processing.util.i.d((AtomicBoolean) eVar.c, true);
        androidx.camera.core.processing.util.i.c((Thread) eVar.e);
        if (((androidx.camera.core.processing.util.f) eVar.m) != fVar) {
            eVar.m = fVar;
            eVar.s(eVar.a);
        }
    }

    @Override // com.facebook.appevents.internal.k
    public void c(File file) {
        com.facebook.appevents.ml.d slave = (com.facebook.appevents.ml.d) this.b;
        Intrinsics.checkNotNullParameter(slave, "$slave");
        Intrinsics.checkNotNullParameter(file, "file");
        slave.g = (com.facebook.appevents.ml.b) this.c;
        slave.f = file;
        Runnable runnable = slave.h;
        if (runnable != null) {
            runnable.run();
        }
    }

    /* JADX WARN: Type inference failed for: r2v8, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // androidx.concurrent.futures.j
    public Object d(androidx.concurrent.futures.i completer) {
        int i = 3;
        int i2 = 1;
        int i3 = 0;
        switch (this.a) {
            case 3:
                C0194q c0194q = (C0194q) this.b;
                c0194q.getClass();
                long jElapsedRealtime = SystemClock.elapsedRealtime();
                Context context = (Context) this.c;
                Executor executor = c0194q.d;
                executor.execute(new RunnableC0193p(c0194q, context, executor, 1, completer, jElapsedRealtime));
                return "CameraX initInternal";
            case 4:
            case 6:
            case 8:
            case 12:
            default:
                RxWorker rxWorker = (RxWorker) this.b;
                Executor backgroundExecutor = rxWorker.getBackgroundExecutor();
                io.reactivex.rxjava3.core.o oVar = io.reactivex.rxjava3.schedulers.e.a;
                ((io.reactivex.rxjava3.core.p) this.c).l(new io.reactivex.rxjava3.android.schedulers.e(backgroundExecutor, i2)).h(new io.reactivex.rxjava3.android.schedulers.e(((androidx.work.impl.utils.taskexecutor.c) rxWorker.getTaskExecutor()).a, i2)).j(new androidx.appcompat.app.L(completer, 14));
                return "converted single to future";
            case 5:
                androidx.camera.core.j0 j0Var = (androidx.camera.core.j0) this.b;
                j0Var.getClass();
                ((AtomicReference) this.c).set(completer);
                return "SurfaceRequest-surface-recreation(" + j0Var.hashCode() + ")";
            case 7:
                androidx.camera.core.processing.c cVar = (androidx.camera.core.processing.c) this.b;
                cVar.getClass();
                Map map = Collections.EMPTY_MAP;
                cVar.e(new RunnableC0130g(cVar, (C0196t) this.c, completer), new RunnableC0131h(i3));
                return "Init GlRenderer";
            case 9:
                androidx.camera.core.processing.concurrent.e eVar = (androidx.camera.core.processing.concurrent.e) this.b;
                eVar.getClass();
                Map map2 = Collections.EMPTY_MAP;
                eVar.e(new RunnableC0130g(eVar, (C0196t) this.c, completer), new RunnableC0131h(i3));
                return "Init GlRenderer";
            case 10:
                androidx.camera.lifecycle.g this$0 = (androidx.camera.lifecycle.g) this.b;
                C0194q cameraX = (C0194q) this.c;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Intrinsics.checkNotNullParameter(cameraX, "$cameraX");
                Intrinsics.checkNotNullParameter(completer, "completer");
                synchronized (this$0.a) {
                    androidx.camera.core.impl.utils.futures.d dVarC = androidx.camera.core.impl.utils.futures.d.c(this$0.d);
                    C0132i c0132i = new C0132i(new androidx.camera.lifecycle.f(cameraX, i3), 9);
                    androidx.camera.core.impl.utils.executor.a aVarA = com.google.android.gms.internal.mlkit_vision_barcode.T.a();
                    dVarC.getClass();
                    androidx.camera.core.impl.utils.futures.b bVarF = androidx.camera.core.impl.utils.futures.i.f(dVarC, c0132i, aVarA);
                    Intrinsics.checkNotNullExpressionValue(bVarF, "cameraX = CameraX(contex…                        )");
                    bVarF.a(new androidx.camera.core.impl.utils.futures.h(i3, bVarF, new com.quizlet.data.repository.searchexplanations.c(2, completer, cameraX)), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
                    Unit unit = Unit.a;
                }
                return "ProcessCameraProvider-initializeCameraX";
            case 11:
                androidx.camera.view.s sVar = (androidx.camera.view.s) this.b;
                sVar.getClass();
                AbstractC3053s1.f(3, "TextureViewImpl");
                androidx.camera.core.j0 j0Var2 = sVar.h;
                androidx.camera.core.impl.utils.executor.a aVarA2 = com.google.android.gms.internal.mlkit_vision_barcode.T.a();
                androidx.camera.core.imagecapture.c cVar2 = new androidx.camera.core.imagecapture.c(completer, i);
                Surface surface = (Surface) this.c;
                j0Var2.a(surface, aVarA2, cVar2);
                return "provideSurface[request=" + sVar.h + " surface=" + surface + "]";
            case 13:
                Intrinsics.checkNotNullParameter(completer, "it");
                AtomicBoolean atomicBoolean = new AtomicBoolean(false);
                completer.a(new androidx.work.r(atomicBoolean, 1), EnumC1440n.a);
                ((Executor) this.b).execute(new RunnableC0130g(atomicBoolean, completer, (Function0) this.c));
                return Unit.a;
        }
    }

    @Override // androidx.camera.core.impl.Q
    public void e(androidx.camera.core.impl.S s) {
        switch (this.a) {
            case 4:
                androidx.camera.core.a0 a0Var = (androidx.camera.core.a0) this.b;
                a0Var.getClass();
                ((androidx.camera.core.impl.Q) this.c).e(a0Var);
                break;
            default:
                androidx.appcompat.app.L l = (androidx.appcompat.app.L) this.b;
                l.getClass();
                ((androidx.camera.core.impl.Q) this.c).e(l);
                break;
        }
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        String strValueOf;
        Context context = (Context) c0Var.get(Context.class);
        switch (((com.facebook.appevents.k) this.c).a) {
            case EventType.VIDEO /* 24 */:
                ApplicationInfo applicationInfo = context.getApplicationInfo();
                if (applicationInfo == null) {
                    strValueOf = "";
                    break;
                } else {
                    strValueOf = String.valueOf(applicationInfo.targetSdkVersion);
                    break;
                }
            case EventType.SUBS /* 25 */:
                ApplicationInfo applicationInfo2 = context.getApplicationInfo();
                if (applicationInfo2 == null) {
                    strValueOf = "";
                    break;
                } else {
                    strValueOf = String.valueOf(applicationInfo2.minSdkVersion);
                    break;
                }
            case EventType.CDN /* 26 */:
                if (!context.getPackageManager().hasSystemFeature("android.hardware.type.television")) {
                    if (!context.getPackageManager().hasSystemFeature("android.hardware.type.watch")) {
                        if (!context.getPackageManager().hasSystemFeature("android.hardware.type.automotive")) {
                            if (!context.getPackageManager().hasSystemFeature("android.hardware.type.embedded")) {
                                strValueOf = "";
                                break;
                            } else {
                                strValueOf = "embedded";
                                break;
                            }
                        } else {
                            strValueOf = "auto";
                            break;
                        }
                    } else {
                        strValueOf = "watch";
                        break;
                    }
                } else {
                    strValueOf = "tv";
                    break;
                }
            default:
                String installerPackageName = context.getPackageManager().getInstallerPackageName(context.getPackageName());
                if (installerPackageName == null) {
                    strValueOf = "";
                    break;
                } else {
                    strValueOf = FirebaseCommonRegistrar.a(installerPackageName);
                    break;
                }
        }
        return new com.google.firebase.platforminfo.a((String) this.b, strValueOf);
    }

    @Override // com.google.android.gms.tasks.e
    public Task g(Object obj) {
        com.google.firebase.remoteconfig.internal.b bVar = (com.google.firebase.remoteconfig.internal.b) this.b;
        com.google.firebase.remoteconfig.internal.c cVar = (com.google.firebase.remoteconfig.internal.c) this.c;
        synchronized (bVar) {
            bVar.c = S3.i(cVar);
        }
        return S3.i(cVar);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:150:0x006d A[EXC_TOP_SPLITTER, PHI: r13
  0x006d: PHI (r13v7 java.io.InputStream) = (r13v6 java.io.InputStream), (r13v8 java.io.InputStream) binds: [B:29:0x006b, B:19:0x005d] A[DONT_GENERATE, DONT_INLINE], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:152:0x007d A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:154:0x0156 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:156:0x00f6 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00ea A[Catch: all -> 0x0074, TRY_LEAVE, TryCatch #16 {all -> 0x0074, blocks: (B:11:0x003e, B:13:0x0041, B:14:0x0042, B:30:0x006d, B:26:0x0066, B:27:0x0069, B:37:0x0078, B:74:0x00e6, B:76:0x00ea, B:78:0x00ed, B:82:0x00f1, B:77:0x00eb), top: B:164:0x001a, inners: #12 }] */
    /* JADX WARN: Type inference failed for: r11v2 */
    /* JADX WARN: Type inference failed for: r11v4 */
    /* JADX WARN: Type inference failed for: r11v5, types: [java.lang.Integer, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r11v6 */
    /* JADX WARN: Type inference failed for: r11v7 */
    /* JADX WARN: Type inference failed for: r11v8 */
    /* JADX WARN: Type inference failed for: r11v9, types: [java.lang.Integer, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r15v20 */
    /* JADX WARN: Type inference failed for: r15v21, types: [java.io.InputStream] */
    /* JADX WARN: Type inference failed for: r15v38, types: [java.io.InputStream] */
    /* JADX WARN: Type inference failed for: r15v4, types: [com.google.android.gms.tasks.Task] */
    /* JADX WARN: Type inference failed for: r15v49 */
    /* JADX WARN: Type inference failed for: r15v5 */
    /* JADX WARN: Type inference failed for: r15v6 */
    /* JADX WARN: Type inference failed for: r15v7 */
    /* JADX WARN: Type inference failed for: r1v5, types: [com.google.firebase.remoteconfig.internal.h] */
    @Override // com.google.android.gms.tasks.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object h(com.google.android.gms.tasks.Task r15) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 484
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.C0143u.h(com.google.android.gms.tasks.Task):java.lang.Object");
    }

    @Override // com.google.firebase.inject.a
    public void i(com.google.firebase.inject.b bVar) {
        ((com.google.firebase.inject.a) this.b).i(bVar);
        ((com.google.firebase.inject.a) this.c).i(bVar);
    }

    public void j() {
        int i = 1;
        String appId = (String) this.c;
        if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.codeless.d.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(appId, "$appId");
            com.facebook.internal.v vVar = (com.facebook.internal.v) this.b;
            boolean zA = false;
            boolean z = vVar != null && vVar.g;
            com.facebook.o oVar = com.facebook.o.a;
            com.facebook.B b = com.facebook.B.a;
            if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.B.class)) {
                try {
                    com.facebook.B.a.e();
                    zA = com.facebook.B.g.a();
                } catch (Throwable th) {
                    com.facebook.internal.instrument.crashshield.a.a(com.facebook.B.class, th);
                }
            }
            if (z && zA) {
                com.facebook.appevents.codeless.d dVar = com.facebook.appevents.codeless.d.a;
                if (com.facebook.internal.instrument.crashshield.a.b(dVar)) {
                    return;
                }
                try {
                    if (com.facebook.appevents.codeless.d.h) {
                        return;
                    }
                    com.facebook.appevents.codeless.d.h = true;
                    com.facebook.o.c().execute(new com.facebook.appevents.v(appId, i));
                } catch (Throwable th2) {
                    com.facebook.internal.instrument.crashshield.a.a(dVar, th2);
                }
            }
        } catch (Throwable th3) {
            com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.codeless.d.class, th3);
        }
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public void onComplete(Task task) {
        ((AbstractServiceC3969f) this.b).a((Intent) this.c);
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) {
        return DefaultInAppMessageViewWrapper.addInAppMessageViewToViewGroup$lambda$12((DefaultInAppMessageViewWrapper) this.b, (View) this.c, view, d0);
    }

    public /* synthetic */ C0143u(androidx.camera.core.processing.c cVar, C0196t c0196t) {
        this.a = 7;
        Map map = Collections.EMPTY_MAP;
        this.b = cVar;
        this.c = c0196t;
    }

    public /* synthetic */ C0143u(androidx.camera.core.processing.concurrent.e eVar, C0196t c0196t) {
        this.a = 9;
        Map map = Collections.EMPTY_MAP;
        this.b = eVar;
        this.c = c0196t;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ C0143u(Executor executor, Function0 function0) {
        this.a = 13;
        this.b = executor;
        this.c = (kotlin.jvm.internal.r) function0;
    }

    @Override // androidx.camera.core.impl.utils.futures.a, com.google.android.datatransport.runtime.scheduling.persistence.e, io.reactivex.rxjava3.functions.h
    public com.google.common.util.concurrent.e apply(Object obj) {
        switch (this.a) {
            case 0:
                V v = (V) this.b;
                v.a();
                ((androidx.camera.core.g0) this.c).a();
                return v.m();
            default:
                List list = (List) obj;
                ((k0) this.b).getClass();
                Objects.toString(list);
                AbstractC3053s1.f(3, "SyncCaptureSessionBase");
                if (list.isEmpty()) {
                    return new androidx.camera.core.impl.utils.futures.k(new IllegalArgumentException("Unable to open capture session without surfaces"), 1);
                }
                if (list.contains(null)) {
                    return new androidx.camera.core.impl.utils.futures.k(new DeferrableSurface$SurfaceClosedException("Surface closed", (androidx.camera.core.impl.J) ((ArrayList) this.c).get(list.indexOf(null))), 1);
                }
                return androidx.camera.core.impl.utils.futures.i.c(list);
        }
    }
}
