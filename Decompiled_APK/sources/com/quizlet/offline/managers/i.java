package com.quizlet.offline.managers;

import android.content.Context;
import android.content.Intent;
import android.util.LongSparseArray;
import androidx.camera.camera2.internal.T;
import com.facebook.z;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBOfflineEntity;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.dialogs.e;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.completable.l;
import io.reactivex.rxjava3.internal.operators.completable.m;
import io.reactivex.rxjava3.internal.operators.maybe.u;
import io.reactivex.rxjava3.internal.operators.observable.B;
import io.reactivex.rxjava3.internal.operators.observable.C4884c;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.single.k;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements b {
    public final EventLogger a;
    public final com.quizlet.data.connectivity.a b;
    public final o c;
    public final androidx.work.impl.model.c d;
    public final o e;
    public final s f;
    public final com.quizlet.local.ormlite.models.term.b g;
    public final LongSparseArray h;
    public boolean i;
    public final LinkedHashMap j;

    public i(EventLogger eventLogger, com.quizlet.data.connectivity.a networkConnectivityManager, o mainThreadScheduler, androidx.work.impl.model.c userProperties, o logicScheduler, s setManager, com.quizlet.local.ormlite.models.term.b offlinePersistenceManager, com.quizlet.infra.legacysyncengine.net.c loader) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(networkConnectivityManager, "networkConnectivityManager");
        Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(logicScheduler, "logicScheduler");
        Intrinsics.checkNotNullParameter(setManager, "setManager");
        Intrinsics.checkNotNullParameter(offlinePersistenceManager, "offlinePersistenceManager");
        Intrinsics.checkNotNullParameter(loader, "loader");
        this.a = eventLogger;
        this.b = networkConnectivityManager;
        this.c = mainThreadScheduler;
        this.d = userProperties;
        this.e = logicScheduler;
        this.f = setManager;
        this.g = offlinePersistenceManager;
        this.h = new LongSparseArray();
        this.i = true;
        this.j = new LinkedHashMap();
        C4887f c4887f = new C4887f(((com.quizlet.remote.connectivity.b) networkConnectivityManager).a.a.q(e.b), 1);
        f fVar = new f(this, 0);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        C4884c c4884cL = new B(c4887f, fVar, gVar, bVar, bVar).l(e.c);
        f fVar2 = new f(this, 1);
        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.e;
        c4884cL.u(fVar2, gVar2, bVar);
        com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.OFFLINE_ENTITY);
        ModelField<DBOfflineEntity, Long> modelField = DBOfflineEntityFields.OFFLINE_STATUS;
        com.quizlet.features.infra.models.b bVar3 = com.quizlet.features.infra.models.b.b;
        Long[] elements = {Long.valueOf(2), Long.valueOf(-1)};
        Intrinsics.checkNotNullParameter(elements, "elements");
        bVar2.c(modelField, C4933y.T(elements), null);
        bVar2.e(DBOfflineEntityFields.STUDYABLE);
        loader.b(bVar2.a(), com.quizlet.infra.legacysyncengine.net.b.a).l(logicScheduler).i(new f(this, 3), gVar2);
    }

    public final k a(long j, boolean z) {
        io.reactivex.rxjava3.internal.operators.flowable.b bVarF = p.f(Boolean.valueOf(((com.quizlet.remote.connectivity.b) this.b).a().a));
        Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
        k kVarH = com.google.android.gms.dynamite.d.f(bVarF, c(j, z)).e(e.d).l(this.e).h(this.c);
        Intrinsics.checkNotNullExpressionValue(kVarH, "observeOn(...)");
        return kVarH;
    }

    public final void b(z offlineSettingsState, List setIdList) {
        Intrinsics.checkNotNullParameter(offlineSettingsState, "offlineSettingsState");
        Intrinsics.checkNotNullParameter(setIdList, "setIdList");
        ArrayList arrayList = new ArrayList();
        for (Object obj : setIdList) {
            if (this.j.get(Long.valueOf(((Number) obj).longValue())) != com.quizlet.features.infra.models.b.d) {
                arrayList.add(obj);
            }
        }
        if (arrayList.isEmpty() || !offlineSettingsState.a.getBoolean("PREF_OFFLINE_TOGGLE", true)) {
            timber.log.c.a.g("User has no sets to preload, or has preloading disabled", new Object[0]);
            return;
        }
        io.reactivex.rxjava3.internal.operators.maybe.j jVar = new io.reactivex.rxjava3.internal.operators.maybe.j(new io.reactivex.rxjava3.internal.operators.maybe.e(this.d.n(), 3), new com.android.billingclient.api.h(arrayList), 1);
        com.quizlet.analytics.marketing.e eVar = new com.quizlet.analytics.marketing.e(arrayList, 18);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        try {
            new u(jVar, gVar, eVar, gVar, bVar).e(new l(new l(new f(this, 2), io.reactivex.rxjava3.internal.functions.d.e, bVar), new com.quizlet.login.authentication.login.a(this, 1)));
        } catch (NullPointerException e) {
            throw e;
        } catch (Throwable th) {
            x7.b(th);
            NullPointerException nullPointerException = new NullPointerException("subscribeActual failed");
            nullPointerException.initCause(th);
            throw nullPointerException;
        }
    }

    public final p c(final long j, final boolean z) {
        if (this.j.get(Long.valueOf(j)) == com.quizlet.features.infra.models.b.c) {
            io.reactivex.rxjava3.internal.operators.flowable.b bVarF = p.f(Boolean.TRUE);
            Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
            return bVarF;
        }
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new io.reactivex.rxjava3.functions.j() { // from class: com.quizlet.offline.managers.c
            @Override // io.reactivex.rxjava3.functions.j
            public final Object get() {
                i iVar = this.a;
                iVar.getClass();
                long j2 = j;
                io.reactivex.rxjava3.internal.operators.flowable.b bVarF2 = p.f(Boolean.valueOf(j2 < 0 || z));
                Intrinsics.checkNotNullExpressionValue(bVarF2, "just(...)");
                LongSparseArray longSparseArray = iVar.h;
                p bVar2 = (p) longSparseArray.get(j2);
                if (bVar2 == null) {
                    if (iVar.j.get(Long.valueOf(j2)) == com.quizlet.features.infra.models.b.d) {
                        bVar2 = p.f(Boolean.FALSE);
                        Intrinsics.checkNotNullExpressionValue(bVar2, "just(...)");
                    } else {
                        bVar2 = new io.reactivex.rxjava3.internal.operators.single.b(new io.reactivex.rxjava3.internal.operators.single.d(new m(iVar.d.n().e(new g(iVar, j2, 0)), new com.quizlet.infra.legacysyncengine.models.serializers.a(13), null, 2), new h(j2), 2));
                        Intrinsics.checkNotNullExpressionValue(bVar2, "cache(...)");
                        longSparseArray.put(j2, bVar2);
                    }
                }
                return com.google.android.gms.dynamite.d.b(bVarF2, bVar2);
            }
        }, 4);
        Intrinsics.checkNotNullExpressionValue(bVar, "defer(...)");
        k kVarH = bVar.l(this.e).h(this.c);
        Intrinsics.checkNotNullExpressionValue(kVarH, "observeOn(...)");
        return kVarH;
    }

    public final void d(Context context, j launchBehavior, Intent intent, com.quizlet.qutils.rx.c intentCallback) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(launchBehavior, "launchBehavior");
        Intrinsics.checkNotNullParameter(intent, "intent");
        Intrinsics.checkNotNullParameter(intentCallback, "intentCallback");
        if (launchBehavior == j.b) {
            e.a aVar = new e.a(context);
            aVar.f(R.string.missing_set_warning_headline);
            aVar.c(R.string.missing_set_warning_message);
            aVar.e(R.string.missing_set_warning_continue, new T(this, intentCallback, intent, 23));
            aVar.b = true;
            aVar.b().show();
        }
    }
}
