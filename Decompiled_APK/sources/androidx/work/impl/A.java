package androidx.work.impl;

import android.app.Activity;
import android.app.usage.StorageStats;
import android.app.usage.StorageStatsManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.TrafficStats;
import android.util.Log;
import androidx.work.C1437k;
import androidx.work.C1446u;
import androidx.work.N;
import com.airbnb.lottie.LottieAnimationView;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import com.google.firebase.perf.network.FirebasePerfOkHttpClient;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.DeleteBuilder;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.features.match.settings.MatchSettingsData;
import com.quizlet.generated.enums.E1;
import com.quizlet.generated.enums.G1;
import com.quizlet.quizletandroid.QuizletApplication;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import okhttp3.H;
import okhttp3.J;

/* loaded from: classes.dex */
public final /* synthetic */ class A implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ A(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // java.util.concurrent.Callable
    public final Object call() throws SQLException {
        ServiceInfo serviceInfo;
        String str;
        com.snowplowanalytics.core.emitter.storage.a aVar;
        int i = -1;
        int i2 = 6;
        boolean z = false;
        z = false;
        z = false;
        z = false;
        z = false;
        z = false;
        z = false;
        z = false;
        final int i3 = 1;
        String str2 = null;
        str2 = null;
        switch (this.a) {
            case 0:
                z zVar = (z) this.b;
                boolean z2 = zVar instanceof x;
                N n = N.a;
                F f = (F) this.c;
                String str3 = f.c;
                androidx.work.impl.model.t tVar = f.j;
                if (z2) {
                    androidx.work.x c1446u = ((x) zVar).a;
                    N n2 = tVar.n(str3);
                    androidx.work.impl.model.n nVarT = f.i.t();
                    WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) nVarT.a;
                    workDatabase_Impl.b();
                    androidx.work.impl.model.h hVar = (androidx.work.impl.model.h) nVarT.c;
                    androidx.sqlite.db.framework.i iVarA = hVar.a();
                    iVarA.g(1, str3);
                    try {
                        workDatabase_Impl.c();
                        try {
                            iVarA.a();
                            workDatabase_Impl.p();
                            if (n2 != null) {
                                if (n2 == N.b) {
                                    boolean z3 = c1446u instanceof androidx.work.w;
                                    androidx.work.impl.model.q qVar = f.a;
                                    String str4 = f.m;
                                    if (z3) {
                                        String str5 = G.a;
                                        androidx.work.z.c().d(str5, "Worker result SUCCESS for " + str4);
                                        if (qVar.c()) {
                                            f.c();
                                        } else {
                                            tVar.y(N.c, str3);
                                            Intrinsics.e(c1446u, "null cannot be cast to non-null type androidx.work.ListenableWorker.Result.Success");
                                            C1437k c1437k = ((androidx.work.w) c1446u).a;
                                            Intrinsics.checkNotNullExpressionValue(c1437k, "success.outputData");
                                            tVar.x(str3, c1437k);
                                            f.g.getClass();
                                            long jCurrentTimeMillis = System.currentTimeMillis();
                                            androidx.work.impl.model.c cVar = f.k;
                                            Iterator it2 = cVar.e(str3).iterator();
                                            while (it2.hasNext()) {
                                                String str6 = (String) it2.next();
                                                if (tVar.n(str6) == N.e) {
                                                    androidx.room.u uVarA = androidx.room.u.a(1, "SELECT COUNT(*)=0 FROM dependency WHERE work_spec_id=? AND prerequisite_id IN (SELECT id FROM workspec WHERE state!=2)");
                                                    uVarA.g(1, str6);
                                                    WorkDatabase_Impl workDatabase_Impl2 = (WorkDatabase_Impl) cVar.b;
                                                    workDatabase_Impl2.b();
                                                    Cursor cursorN = W1.N(workDatabase_Impl2, uVarA, false);
                                                    try {
                                                        if ((cursorN.moveToFirst() && cursorN.getInt(0) != 0) != false) {
                                                            androidx.work.z.c().d(G.a, "Setting status to enqueued for ".concat(str6));
                                                            tVar.y(n, str6);
                                                            tVar.w(jCurrentTimeMillis, str6);
                                                        }
                                                    } finally {
                                                        cursorN.close();
                                                        uVarA.i();
                                                    }
                                                }
                                            }
                                        }
                                    } else if (c1446u instanceof androidx.work.v) {
                                        String str7 = G.a;
                                        androidx.work.z.c().d(str7, "Worker result RETRY for " + str4);
                                        f.b(-256);
                                        z = true;
                                    } else {
                                        String str8 = G.a;
                                        androidx.work.z.c().d(str8, "Worker result FAILURE for " + str4);
                                        if (qVar.c()) {
                                            f.c();
                                        } else {
                                            if (c1446u == null) {
                                                c1446u = new C1446u();
                                            }
                                            f.d(c1446u);
                                        }
                                    }
                                } else if (!n2.a()) {
                                    f.b(-512);
                                    z = true;
                                }
                            }
                        } finally {
                            workDatabase_Impl.k();
                        }
                    } finally {
                        hVar.n(iVarA);
                    }
                } else if (zVar instanceof w) {
                    f.d(((w) zVar).a);
                } else {
                    if (!(zVar instanceof y)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    int i4 = ((y) zVar).a;
                    N n3 = tVar.n(str3);
                    if (n3 == null || n3.a()) {
                        String str9 = G.a;
                        androidx.work.z zVarC = androidx.work.z.c();
                        Objects.toString(n3);
                        zVarC.getClass();
                    } else {
                        String str10 = G.a;
                        androidx.work.z zVarC2 = androidx.work.z.c();
                        n3.toString();
                        zVarC2.getClass();
                        tVar.y(n, str3);
                        tVar.z(i4, str3);
                        tVar.q(-1L, str3);
                        z = true;
                    }
                }
                return Boolean.valueOf(z);
            case 1:
                LottieAnimationView lottieAnimationView = (LottieAnimationView) this.b;
                boolean z4 = lottieAnimationView.m;
                String str11 = (String) this.c;
                if (!z4) {
                    return com.airbnb.lottie.l.b(lottieAnimationView.getContext(), str11, null);
                }
                Context context = lottieAnimationView.getContext();
                HashMap map = com.airbnb.lottie.l.a;
                return com.airbnb.lottie.l.b(context, str11, "asset_" + str11);
            case 2:
                com.quizlet.data.repository.explanations.myexplanations.a this$0 = (com.quizlet.data.repository.explanations.myexplanations.a) this.b;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                com.facebook.m callable = (com.facebook.m) this.c;
                Intrinsics.checkNotNullParameter(callable, "$callable");
                try {
                    this$0.b = callable.call();
                    return null;
                } finally {
                    CountDownLatch countDownLatch = (CountDownLatch) this$0.c;
                    if (countDownLatch != null) {
                        countDownLatch.countDown();
                    }
                }
            case 3:
                Context context2 = (Context) this.b;
                Intent intent = (Intent) this.c;
                com.google.firebase.messaging.u uVarD = com.google.firebase.messaging.u.d();
                uVarD.getClass();
                Log.isLoggable("FirebaseMessaging", 3);
                ((ArrayDeque) uVarD.d).offer(intent);
                Intent intent2 = new Intent("com.google.firebase.MESSAGING_EVENT");
                intent2.setPackage(context2.getPackageName());
                synchronized (uVarD) {
                    try {
                        String str12 = (String) uVarD.a;
                        if (str12 != null) {
                            str2 = str12;
                        } else {
                            ResolveInfo resolveInfoResolveService = context2.getPackageManager().resolveService(intent2, 0);
                            if (resolveInfoResolveService == null || (serviceInfo = resolveInfoResolveService.serviceInfo) == null) {
                                Log.e("FirebaseMessaging", "Failed to resolve target intent service, skipping classname enforcement");
                            } else if (!context2.getPackageName().equals(serviceInfo.packageName) || (str = serviceInfo.name) == null) {
                                Log.e("FirebaseMessaging", "Error resolving target intent service, skipping classname enforcement. Resolved service was: " + serviceInfo.packageName + "/" + serviceInfo.name);
                            } else {
                                if (str.startsWith(".")) {
                                    uVarD.a = context2.getPackageName() + serviceInfo.name;
                                } else {
                                    uVarD.a = serviceInfo.name;
                                }
                                str2 = (String) uVarD.a;
                            }
                        }
                    } finally {
                    }
                }
                if (str2 != null) {
                    Log.isLoggable("FirebaseMessaging", 3);
                    intent2.setClassName(context2.getPackageName(), str2);
                }
                try {
                    if ((uVarD.f(context2) ? com.google.firebase.messaging.D.b(context2, intent2) : context2.startService(intent2)) == null) {
                        Log.e("FirebaseMessaging", "Error while delivering the message: ServiceIntent not found.");
                        i = 404;
                    }
                } catch (IllegalStateException e) {
                    Log.e("FirebaseMessaging", "Failed to start service while in background: " + e);
                    i = 402;
                } catch (SecurityException e2) {
                    Log.e("FirebaseMessaging", "Error while delivering the message to the serviceIntent", e2);
                    i = 401;
                }
                return Integer.valueOf(i);
            case 4:
                com.google.firebase.remoteconfig.internal.b bVar = (com.google.firebase.remoteconfig.internal.b) this.b;
                com.google.firebase.remoteconfig.internal.c cVar2 = (com.google.firebase.remoteconfig.internal.c) this.c;
                com.google.firebase.remoteconfig.internal.k kVar = bVar.b;
                synchronized (kVar) {
                    FileOutputStream fileOutputStreamOpenFileOutput = kVar.a.openFileOutput(kVar.b, 0);
                    try {
                        fileOutputStreamOpenFileOutput.write(cVar2.a.toString().getBytes("UTF-8"));
                    } finally {
                        fileOutputStreamOpenFileOutput.close();
                    }
                }
                return null;
            case 5:
                return ModelIdentityProvider.generateLocalIdsIfNeededAsync$lambda$4((List) this.b, (ModelIdentityProvider) this.c);
            case 6:
                return ModelIdentityProvider.queryDbForInitialLocalId$lambda$0((ModelIdentityProvider) this.b, (ModelType) this.c);
            case 7:
                return ModelIdentityProvider.generateLocalIdIfNeededAsync$lambda$1((DBModel) this.b, (ModelIdentityProvider) this.c);
            case 8:
                com.quizlet.data.repository.folderset.c cVar3 = (com.quizlet.data.repository.folderset.c) ((com.quizlet.data.repository.metering.j) this.b).b;
                MatchSettingsData settings = (MatchSettingsData) this.c;
                Intrinsics.checkNotNullParameter(settings, "settings");
                if (((com.quizlet.features.infra.studysetting.managers.a) cVar3.d) == null) {
                    throw new IllegalStateException("Must set StudySettingManger before calling any other method");
                }
                StudyableModelData studyableModelData = (StudyableModelData) cVar3.c;
                ((com.facebook.z) cVar3.b).c(studyableModelData.k(), studyableModelData.getStudyableType(), settings.a);
                long j = settings.b ? 2L : 0L;
                long j2 = settings.c ? 4L : 0L;
                long j3 = settings.d ? 16L : 0L;
                com.quizlet.features.infra.studysetting.managers.a aVar2 = (com.quizlet.features.infra.studysetting.managers.a) cVar3.d;
                if (aVar2 != null) {
                    aVar2.n(E1.MATCH_MODE_SIDES, j | j2 | j3);
                    return Unit.a;
                }
                Intrinsics.m("studySettingManager");
                throw null;
            case 9:
                List list = (List) this.b;
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                Iterator it3 = list.iterator();
                while (it3.hasNext()) {
                    arrayList.add(((Dao) this.c).createOrUpdate(it3.next()));
                }
                return arrayList;
            case 10:
                int i5 = QuizletApplication.m;
                QuizletApplication quizletApplication = (QuizletApplication) this.b;
                ((com.quizlet.quizletandroid.lib.b) this.c).a.edit().putInt("PREFS_VERSION_CODE", 2601637).apply();
                final com.quizlet.quizletandroid.util.n nVar = (com.quizlet.quizletandroid.util.n) quizletApplication.f.get();
                nVar.getClass();
                final int i6 = z ? 1 : 0;
                io.reactivex.rxjava3.internal.operators.flowable.b bVar2 = new io.reactivex.rxjava3.internal.operators.flowable.b(new Callable() { // from class: com.quizlet.quizletandroid.util.k
                    @Override // java.util.concurrent.Callable
                    public final Object call() throws IOException {
                        long dataBytes;
                        switch (i6) {
                            case 0:
                                Context context3 = nVar.a;
                                Object systemService = context3.getSystemService("storagestats");
                                StorageStatsManager storageStatsManager = systemService instanceof StorageStatsManager ? (StorageStatsManager) systemService : null;
                                if (storageStatsManager != null) {
                                    try {
                                        StorageStats storageStatsQueryStatsForUid = storageStatsManager.queryStatsForUid(context3.getApplicationInfo().storageUuid, context3.getApplicationInfo().uid);
                                        Intrinsics.checkNotNullExpressionValue(storageStatsQueryStatsForUid, "queryStatsForUid(...)");
                                        dataBytes = storageStatsQueryStatsForUid.getDataBytes();
                                    } catch (IOException unused) {
                                    }
                                } else {
                                    dataBytes = -1;
                                }
                                return Long.valueOf(dataBytes);
                            default:
                                n nVar2 = nVar;
                                return Long.valueOf(nVar2.d.a(nVar2.a));
                        }
                    }
                }, i2);
                Intrinsics.checkNotNullExpressionValue(bVar2, "fromCallable(...)");
                com.quizlet.quizletandroid.managers.audio.g gVar = nVar.b;
                gVar.getClass();
                io.reactivex.rxjava3.internal.operators.flowable.b bVar3 = new io.reactivex.rxjava3.internal.operators.flowable.b(new androidx.work.impl.utils.d(gVar, 13), i2);
                Intrinsics.checkNotNullExpressionValue(bVar3, "fromCallable(...)");
                com.quizlet.quizletandroid.ui.common.images.loading.offline.c cVar4 = nVar.c;
                cVar4.getClass();
                io.reactivex.rxjava3.internal.operators.flowable.b bVar4 = new io.reactivex.rxjava3.internal.operators.flowable.b(new androidx.work.impl.utils.d(cVar4, 14), i2);
                Intrinsics.checkNotNullExpressionValue(bVar4, "fromCallable(...)");
                io.reactivex.rxjava3.internal.operators.flowable.b bVar5 = new io.reactivex.rxjava3.internal.operators.flowable.b(new Callable() { // from class: com.quizlet.quizletandroid.util.k
                    @Override // java.util.concurrent.Callable
                    public final Object call() throws IOException {
                        long dataBytes;
                        switch (i3) {
                            case 0:
                                Context context3 = nVar.a;
                                Object systemService = context3.getSystemService("storagestats");
                                StorageStatsManager storageStatsManager = systemService instanceof StorageStatsManager ? (StorageStatsManager) systemService : null;
                                if (storageStatsManager != null) {
                                    try {
                                        StorageStats storageStatsQueryStatsForUid = storageStatsManager.queryStatsForUid(context3.getApplicationInfo().storageUuid, context3.getApplicationInfo().uid);
                                        Intrinsics.checkNotNullExpressionValue(storageStatsQueryStatsForUid, "queryStatsForUid(...)");
                                        dataBytes = storageStatsQueryStatsForUid.getDataBytes();
                                    } catch (IOException unused) {
                                    }
                                } else {
                                    dataBytes = -1;
                                }
                                return Long.valueOf(dataBytes);
                            default:
                                n nVar2 = nVar;
                                return Long.valueOf(nVar2.d.a(nVar2.a));
                        }
                    }
                }, i2);
                Intrinsics.checkNotNullExpressionValue(bVar5, "fromCallable(...)");
                io.reactivex.rxjava3.core.p pVarN = io.reactivex.rxjava3.core.p.n(bVar2, bVar3, bVar4, bVar5, new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(nVar));
                Intrinsics.checkNotNullExpressionValue(pVarN, "zip(...)");
                pVarN.l(nVar.f).i(new com.quizlet.quizletandroid.util.m(nVar), io.reactivex.rxjava3.internal.functions.d.e);
                return Boolean.TRUE;
            case 11:
                File fileB = ((com.quizlet.quizletandroid.managers.audio.g) this.b).b.b((String) ((com.quizlet.qutils.data.offline.d) this.c).a);
                if (fileB.exists()) {
                    fileB.delete();
                }
                return io.reactivex.rxjava3.internal.operators.completable.f.a;
            case 12:
                com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = (com.quizlet.quizletandroid.ui.setcreation.managers.i) this.b;
                iVar.getClass();
                DeleteBuilder deleteBuilder = ((DatabaseHelper) this.c).j(Models.SESSION).deleteBuilder();
                deleteBuilder.where().eq(DBSessionFields.STUDYABLE.getDatabaseColumnName(), iVar.k).and().eq(DBSessionFields.ITEM_TYPE.getDatabaseColumnName(), Integer.valueOf(G1.SET.b()));
                timber.log.c.a.a("Deleted %d sessions", Integer.valueOf(deleteBuilder.delete()));
                iVar.j.g(new com.google.firebase.crashlytics.internal.metadata.q(iVar, 17));
                return null;
            case 13:
                androidx.work.impl.background.greedy.d this$02 = (androidx.work.impl.background.greedy.d) this.b;
                Activity context3 = (Activity) this.c;
                Intrinsics.checkNotNullParameter(this$02, "this$0");
                Intrinsics.checkNotNullParameter(context3, "$context");
                com.quizlet.quizletandroid.ui.common.images.capture.a aVar3 = com.snowplowanalytics.core.emitter.storage.a.a;
                this$02.getClass();
                synchronized (aVar3) {
                    Intrinsics.checkNotNullParameter(context3, "context");
                    Intrinsics.checkNotNullParameter("appTracker", "namespace");
                    HashMap map2 = com.snowplowanalytics.core.emitter.storage.a.b;
                    if (map2.containsKey("appTracker")) {
                        Object obj = map2.get("appTracker");
                        Intrinsics.d(obj);
                        aVar = (com.snowplowanalytics.core.emitter.storage.a) obj;
                    } else {
                        String str13 = "snowplowEvents-" + new Regex("[^a-zA-Z0-9_]+").replace("appTracker", "-") + ".sqlite";
                        com.quizlet.quizletandroid.ui.common.images.capture.a.k(context3, str13);
                        Context applicationContext = context3.getApplicationContext();
                        Intrinsics.checkNotNullExpressionValue(applicationContext, "context.applicationContext");
                        com.snowplowanalytics.core.emitter.storage.a aVar4 = new com.snowplowanalytics.core.emitter.storage.a(applicationContext, str13, null, 1);
                        map2.put("appTracker", aVar4);
                        aVar = aVar4;
                    }
                }
                this$02.d = aVar;
                if (!this$02.b()) {
                    com.snowplowanalytics.core.emitter.storage.a aVar5 = (com.snowplowanalytics.core.emitter.storage.a) this$02.d;
                    SQLiteDatabase writableDatabase = aVar5 != null ? aVar5.getWritableDatabase() : null;
                    this$02.c = writableDatabase;
                    if (writableDatabase != null) {
                        writableDatabase.enableWriteAheadLogging();
                    }
                }
                Intrinsics.checkNotNullExpressionValue("d", "TAG");
                SQLiteDatabase sQLiteDatabase = (SQLiteDatabase) this$02.c;
                com.snowplowanalytics.core.tracker.e.a("d", "DB Path: %s", sQLiteDatabase != null ? sQLiteDatabase.getPath() : null);
                return null;
            default:
                com.snowplowanalytics.snowplow.network.f this$03 = (com.snowplowanalytics.snowplow.network.f) this.b;
                Intrinsics.checkNotNullParameter(this$03, "this$0");
                okhttp3.C request = (okhttp3.C) this.c;
                Intrinsics.checkNotNullParameter(request, "$request");
                String TAG = this$03.a;
                try {
                    Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
                    com.snowplowanalytics.core.tracker.e.e(TAG, "Sending request: %s", request);
                    TrafficStats.setThreadStatsTag(1);
                    okhttp3.A a = this$03.g;
                    H hExecute = a != null ? FirebasePerfOkHttpClient.execute(a.c(request)) : null;
                    if (hExecute != null) {
                        J j4 = hExecute.g;
                        if (j4 != null) {
                            j4.close();
                        }
                        i = hExecute.d;
                    }
                } catch (IOException e3) {
                    Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
                    com.snowplowanalytics.core.tracker.e.b(TAG, "Request sending failed: %s", e3.toString());
                }
                return Integer.valueOf(i);
        }
    }
}
