package com.google.android.datatransport.cct.internal;

import android.content.Context;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraManager;
import android.net.Uri;
import android.text.TextUtils;
import android.util.Log;
import androidx.appcompat.app.L;
import androidx.appcompat.widget.C0122z;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.view.PreviewView;
import androidx.compose.animation.d0;
import com.google.android.gms.internal.ads.A7;
import com.google.android.gms.internal.ads.AbstractC2025es;
import com.google.android.gms.internal.ads.C1732Mb;
import com.google.android.gms.internal.ads.C1849aq;
import com.google.android.gms.internal.ads.C2195in;
import com.google.android.gms.internal.ads.C2232ji;
import com.google.android.gms.internal.ads.C2403nh;
import com.google.android.gms.internal.ads.C2411np;
import com.google.android.gms.internal.ads.C2542qr;
import com.google.android.gms.internal.ads.C2574rh;
import com.google.android.gms.internal.ads.C2660th;
import com.google.android.gms.internal.ads.C2859y7;
import com.google.android.gms.internal.ads.InterfaceC2488pg;
import com.google.android.gms.internal.ads.InterfaceC2751vm;
import com.google.android.gms.internal.ads.Lh;
import com.google.android.gms.internal.ads.Qv;
import com.google.android.gms.internal.ads.Ug;
import com.google.android.gms.internal.ads.Vp;
import com.google.android.gms.internal.ads.Xv;
import com.google.android.gms.internal.ads.zzdwf;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.RelationshipGraph;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.identity.UnboundModelSingleFieldIdentity;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.db.data.orm.Filter;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.query.BaseQuery;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import com.quizlet.infra.legacysyncengine.models.identity.QueryIdFieldChangeMapper;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class s {
    public Object a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;
    public Object h;
    public Object i;

    public s(C1849aq c1849aq, Vp vp, C2403nh c2403nh, C2574rh c2574rh, C2411np c2411np, Ug ug, Lh lh, C2660th c2660th, C2232ji c2232ji) {
        this.b = c1849aq;
        this.c = vp;
        this.d = c2403nh;
        this.e = c2574rh;
        this.f = c2411np;
        this.g = ug;
        this.a = lh;
        this.h = c2660th;
        this.i = c2232ji;
    }

    public static final io.reactivex.rxjava3.internal.operators.single.g a(s sVar, List list, com.quizlet.qutils.data.offline.d dVar, com.quizlet.offline.data.a aVar) {
        sVar.getClass();
        io.reactivex.rxjava3.internal.operators.single.g gVar = new io.reactivex.rxjava3.internal.operators.single.g(new C4885d(io.reactivex.rxjava3.core.i.o(list).s((io.reactivex.rxjava3.core.o) sVar.a), new androidx.work.impl.model.e(25, aVar, dVar), 0), com.quizlet.quizletandroid.data.management.c.b, 2);
        Intrinsics.checkNotNullExpressionValue(gVar, "onErrorResumeNext(...)");
        return gVar;
    }

    public static void b(Map map, List list, com.snowplowanalytics.core.statemachine.f fVar) {
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            List linkedList = (List) map.get(str);
            if (linkedList == null) {
                linkedList = new LinkedList();
                map.put(str, linkedList);
            }
            linkedList.add(fVar);
        }
    }

    public static io.reactivex.rxjava3.core.a i(String str, com.quizlet.offline.data.a aVar) {
        if (str == null) {
            return io.reactivex.rxjava3.internal.operators.completable.f.a;
        }
        return aVar.b(new com.quizlet.qutils.data.offline.d(str, com.quizlet.qutils.data.offline.c.a, true, com.quizlet.qutils.data.offline.b.a, com.quizlet.qutils.data.offline.a.d));
    }

    public static void p(HashMap map, List list, com.snowplowanalytics.core.statemachine.f fVar) {
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            List list2 = (List) map.get((String) it2.next());
            if (list2 != null) {
                list2.remove(fVar);
            }
        }
    }

    public synchronized void c(com.snowplowanalytics.core.tracker.q event) {
        try {
            Intrinsics.checkNotNullParameter(event, "event");
            String str = event.a;
            if (str == null) {
                str = null;
            }
            LinkedList linkedList = new LinkedList();
            List list = (List) ((HashMap) this.g).get(str);
            if (list != null) {
                linkedList.addAll(list);
            }
            List list2 = (List) ((HashMap) this.g).get("*");
            if (list2 != null) {
                linkedList.addAll(list2);
            }
            if (!linkedList.isEmpty()) {
                com.snowplowanalytics.core.emitter.c.a(false, "s", new com.skydoves.balloon.compose.a(4, linkedList, event));
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public com.google.mlkit.vision.camera.a d(PreviewView cameraSourceView) throws CameraAccessException {
        Intrinsics.checkNotNullParameter(cameraSourceView, "cameraSourceView");
        CameraManager cameraManager = (CameraManager) this.f;
        String[] cameraIdList = cameraManager.getCameraIdList();
        Intrinsics.checkNotNullExpressionValue(cameraIdList, "getCameraIdList(...)");
        int length = cameraIdList.length;
        int i = 0;
        int i2 = 0;
        while (true) {
            if (i2 >= length) {
                break;
            }
            CameraCharacteristics cameraCharacteristics = cameraManager.getCameraCharacteristics(cameraIdList[i2]);
            Intrinsics.checkNotNullExpressionValue(cameraCharacteristics, "getCameraCharacteristics(...)");
            Integer num = (Integer) cameraCharacteristics.get(CameraCharacteristics.LENS_FACING);
            if (num != null && num.intValue() == 1) {
                i = 1;
                break;
            }
            i2++;
        }
        Context context = cameraSourceView.getContext();
        com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 12);
        com.google.android.gms.common.internal.u.i(context, "Context must be non-null.");
        Context applicationContext = context.getApplicationContext();
        if (applicationContext != null) {
            context = applicationContext;
        }
        C0122z c0122z = new C0122z(context, new com.quizlet.data.interactor.school.b(13, (com.google.mlkit.vision.barcode.internal.c) this.e, bVar), i, 18);
        Intrinsics.checkNotNullExpressionValue(c0122z, "build(...)");
        return new com.google.mlkit.vision.camera.a(c0122z, cameraSourceView);
    }

    public io.reactivex.rxjava3.internal.operators.maybe.j e(DBStudySet dBStudySet, com.quizlet.qutils.data.offline.d dVar, long j) {
        io.reactivex.rxjava3.internal.operators.maybe.j jVar = new io.reactivex.rxjava3.internal.operators.maybe.j(new io.reactivex.rxjava3.internal.operators.maybe.j(io.reactivex.rxjava3.core.g.c(new com.quizlet.quizletandroid.data.management.a(dBStudySet, dVar, j)), new com.quizlet.login.common.interactors.d(this, 1), 0), new com.quizlet.data.interactor.achievements.f(this, 27), 0);
        Intrinsics.checkNotNullExpressionValue(jVar, "flatMap(...)");
        return jVar;
    }

    public io.reactivex.rxjava3.internal.operators.single.g f(com.quizlet.quizletandroid.data.management.a aVar) {
        com.quizlet.qutils.data.offline.d dVar = aVar.b;
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.TERM);
        bVar.b(Long.valueOf(aVar.a.getId()), DBTermFields.SET);
        com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
        Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = n(dVar, aVarA).e(new androidx.work.impl.model.l(aVar, false, this, 25));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    public io.reactivex.rxjava3.core.g g(com.quizlet.qutils.data.offline.d dVar, String str) {
        if (str == null) {
            io.reactivex.rxjava3.internal.operators.maybe.l lVarC = io.reactivex.rxjava3.core.g.c(Unit.a);
            Intrinsics.checkNotNullExpressionValue(lVarC, "just(...)");
            return lVarC;
        }
        io.reactivex.rxjava3.internal.operators.maybe.j jVar = new io.reactivex.rxjava3.internal.operators.maybe.j(new io.reactivex.rxjava3.internal.operators.maybe.s(((com.quizlet.quizletandroid.managers.audio.g) this.b).a(dVar.a(str, com.quizlet.qutils.data.offline.b.c)), io.reactivex.rxjava3.internal.functions.d.f, 0), com.quizlet.quizletandroid.data.management.c.c, 1);
        Intrinsics.checkNotNullExpressionValue(jVar, "map(...)");
        return jVar;
    }

    public com.quizlet.infra.legacysyncengine.tasks.read.b h(IdMappedQuery idMappedQuery) {
        return new com.quizlet.infra.legacysyncengine.tasks.read.b(idMappedQuery, (DatabaseHelper) this.b, ((ExecutionRouter) this.e).c());
    }

    public com.google.firebase.crashlytics.internal.settings.a j(int i) {
        com.google.firebase.crashlytics.internal.settings.a aVar = null;
        try {
            if (!AbstractC0147y.a(2, i)) {
                JSONObject jSONObjectN = ((L) this.f).N();
                if (jSONObjectN != null) {
                    com.google.firebase.crashlytics.internal.settings.a aVarI = ((com.google.firebase.crashlytics.internal.settings.b) this.d).i(jSONObjectN);
                    jSONObjectN.toString();
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    ((com.onetrust.otpublishers.headless.Internal.Helper.h) this.e).getClass();
                    long jCurrentTimeMillis = System.currentTimeMillis();
                    if (!AbstractC0147y.a(3, i) && aVarI.c < jCurrentTimeMillis) {
                        Log.isLoggable("FirebaseCrashlytics", 2);
                        return null;
                    }
                    try {
                        Log.isLoggable("FirebaseCrashlytics", 2);
                        return aVarI;
                    } catch (Exception e) {
                        e = e;
                        aVar = aVarI;
                        Log.e("FirebaseCrashlytics", "Failed to get cached settings", e);
                        return aVar;
                    }
                }
                Log.isLoggable("FirebaseCrashlytics", 3);
            }
            return null;
        } catch (Exception e2) {
            e = e2;
        }
    }

    public io.reactivex.rxjava3.core.p k(com.quizlet.qutils.data.offline.d dVar, long j, boolean z) {
        Object next;
        Set<Long> fieldValues;
        if (j <= 0) {
            timber.log.c.a.d(d0.o(j, "Not a valid userID (", "). Why are we trying to save things?"), new Object[0]);
            io.reactivex.rxjava3.internal.operators.flowable.b bVarF = io.reactivex.rxjava3.core.p.f(Collections.EMPTY_LIST);
            Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
            return bVarF;
        }
        IdMappedQuery setQuery = ((QueryIdFieldChangeMapper) this.d).convertStaleLocalIds((BaseQuery) dVar.a);
        Intrinsics.checkNotNullExpressionValue(setQuery, "convertStaleLocalIds(...)");
        Intrinsics.checkNotNullParameter(setQuery, "setQuery");
        com.google.common.collect.o filters = setQuery.getFilters();
        Intrinsics.checkNotNullExpressionValue(filters, "getFilters(...)");
        Iterator<E> it2 = filters.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (Intrinsics.b(((Filter) next).getField(), DBStudySetFields.ID)) {
                break;
            }
        }
        Filter filter = (Filter) next;
        if (filter == null || (fieldValues = filter.getFieldValues()) == null) {
            fieldValues = Collections.EMPTY_SET;
            Intrinsics.checkNotNullExpressionValue(fieldValues, "emptySet(...)");
        }
        if (fieldValues == null) {
            timber.log.c.a.d("No IDs requested, invalid Query?", new Object[0]);
            io.reactivex.rxjava3.internal.operators.flowable.b bVarF2 = io.reactivex.rxjava3.core.p.f(Collections.EMPTY_LIST);
            Intrinsics.checkNotNullExpressionValue(bVarF2, "just(...)");
            return bVarF2;
        }
        com.quizlet.qutils.data.offline.a aVar = com.quizlet.qutils.data.offline.a.d;
        com.quizlet.qutils.data.offline.a aVar2 = dVar.e;
        if (aVar2 != aVar && aVar2 != com.quizlet.qutils.data.offline.a.c) {
            io.reactivex.rxjava3.internal.operators.single.g gVarG = n(dVar, (com.quizlet.infra.legacysyncengine.orm.query.a) dVar.a).e(new androidx.work.impl.model.v(25, this, fieldValues)).e(new com.quizlet.quizletandroid.data.management.g(z, this, dVar, j, 1)).e(new com.google.firebase.crashlytics.internal.common.j(this, 27)).e(new com.quizlet.local.ormlite.models.term.b(this, 4)).e(new com.quizlet.quizletandroid.data.management.e(this, 1)).g(com.quizlet.quizletandroid.data.management.c.d);
            Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
            return gVarG;
        }
        timber.log.c.a.d("HitNetwork setting not compatible with getting data from the server : " + aVar2, new Object[0]);
        io.reactivex.rxjava3.internal.operators.flowable.b bVarF3 = io.reactivex.rxjava3.core.p.f(Collections.EMPTY_LIST);
        Intrinsics.checkNotNullExpressionValue(bVarF3, "just(...)");
        return bVarF3;
    }

    public com.google.firebase.crashlytics.internal.settings.a l() {
        return (com.google.firebase.crashlytics.internal.settings.a) ((AtomicReference) this.h).get();
    }

    public io.reactivex.rxjava3.core.p m(long j) {
        io.reactivex.rxjava3.subjects.r rVar = (io.reactivex.rxjava3.subjects.r) this.i;
        return rVar.s() ? rVar : new io.reactivex.rxjava3.internal.operators.single.d(new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.db.data.database.a(this, j, 1), 6), new com.quizlet.features.match.game.b(rVar, 0), 2).l((io.reactivex.rxjava3.core.o) this.h);
    }

    public io.reactivex.rxjava3.core.p n(com.quizlet.qutils.data.offline.d payload, com.quizlet.infra.legacysyncengine.orm.query.a query) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        Intrinsics.checkNotNullParameter(query, "query");
        if (payload.e == com.quizlet.qutils.data.offline.a.a) {
            io.reactivex.rxjava3.internal.operators.flowable.b bVarF = io.reactivex.rxjava3.core.p.f(Collections.EMPTY_LIST);
            Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
            return bVarF;
        }
        io.reactivex.rxjava3.internal.operators.single.k kVarF = ((s) this.e).h(((QueryIdFieldChangeMapper) this.d).convertStaleLocalIds(query)).f();
        Intrinsics.checkNotNullExpressionValue(kVarF, "single(...)");
        return kVarF;
    }

    public io.reactivex.rxjava3.internal.operators.single.k o(com.quizlet.infra.legacysyncengine.orm.query.a query) {
        Intrinsics.checkNotNullParameter(query, "query");
        io.reactivex.rxjava3.internal.operators.single.k kVarH = new io.reactivex.rxjava3.internal.operators.completable.m(new com.quizlet.data.repository.classfolder.b(8, this, query), new com.quizlet.data.repository.searchexplanations.c(24, this, query), new com.quizlet.billing.manager.b(9, this, query), 3).h((io.reactivex.rxjava3.core.o) this.h);
        Intrinsics.checkNotNullExpressionValue(kVarH, "observeOn(...)");
        return kVarH;
    }

    public synchronized void q(String stateIdentifier) {
        Intrinsics.checkNotNullParameter(stateIdentifier, "identifier");
        com.snowplowanalytics.core.statemachine.f fVar = (com.snowplowanalytics.core.statemachine.f) ((HashMap) this.b).remove(stateIdentifier);
        if (fVar == null) {
            return;
        }
        ((HashMap) this.c).remove(fVar);
        com.quizlet.quizletandroid.k kVar = (com.quizlet.quizletandroid.k) this.i;
        kVar.getClass();
        Intrinsics.checkNotNullParameter(stateIdentifier, "stateIdentifier");
        ((HashMap) kVar.b).remove(stateIdentifier);
        p((HashMap) this.d, fVar.k(), fVar);
        p((HashMap) this.e, fVar.d(), fVar);
        p((HashMap) this.f, fVar.f(), fVar);
        p((HashMap) this.g, fVar.j(), fVar);
        p((HashMap) this.a, fVar.c(), fVar);
        p((HashMap) this.h, fVar.a(), fVar);
    }

    public void r() {
        Map map;
        Iterator it2;
        Map map2;
        boolean z;
        com.quizlet.infra.legacysyncengine.net.constants.a aVar = com.quizlet.infra.legacysyncengine.net.constants.a.b;
        com.quizlet.infra.legacysyncengine.net.constants.a aVar2 = (com.quizlet.infra.legacysyncengine.net.constants.a) this.h;
        boolean zEquals = aVar.equals(aVar2);
        boolean z2 = !zEquals;
        HashMap map3 = new HashMap();
        boolean zEquals2 = aVar.equals(aVar2);
        Map map4 = (Map) this.a;
        com.quizlet.infra.legacysyncengine.tasks.parse.h hVar = (com.quizlet.infra.legacysyncengine.tasks.parse.h) this.g;
        if (!zEquals2) {
            Iterator it3 = hVar.a().iterator();
            while (it3.hasNext()) {
                ModelType modelType = (ModelType) it3.next();
                List list = (List) map4.get(modelType);
                if (list != null) {
                    ((ModelIdentityProvider) this.d).updateLocalId((List) hVar.a.get(modelType), (List) hVar.b.get(modelType), list);
                }
            }
        }
        Iterator it4 = hVar.a().iterator();
        while (true) {
            boolean zHasNext = it4.hasNext();
            map = hVar.a;
            if (!zHasNext) {
                break;
            }
            ModelType modelType2 = (ModelType) it4.next();
            ArrayList arrayList = new ArrayList();
            List list2 = (List) map.get(modelType2);
            if (list2 != null) {
                arrayList.addAll(list2);
            }
            Map map5 = hVar.b;
            List list3 = (List) map5.get(modelType2);
            if (list3 != null) {
                arrayList.addAll(list3);
            }
            List list4 = (List) map4.get(modelType2);
            androidx.compose.foundation.text.input.internal.u uVar = (androidx.compose.foundation.text.input.internal.u) this.f;
            uVar.getClass();
            ArrayList arrayList2 = new ArrayList();
            arrayList2.addAll(arrayList);
            Map mapIdentityMap = ModelIdentityProvider.identityMap(list4);
            int i = 0;
            while (true) {
                DBModel dBModel = null;
                if (i >= arrayList2.size()) {
                    break;
                }
                DBModel dBModel2 = (DBModel) arrayList2.get(i);
                if (mapIdentityMap.isEmpty() || (dBModel = (DBModel) mapIdentityMap.remove(dBModel2.getIdentity())) != null || ModelIdentityProvider.getSingleIdentityField(dBModel2.getModelType()) == null) {
                    it2 = it4;
                    map2 = map4;
                    z = zEquals;
                } else {
                    it2 = it4;
                    map2 = map4;
                    z = zEquals;
                    dBModel = (DBModel) mapIdentityMap.remove(new UnboundModelSingleFieldIdentity(dBModel2.getModelType(), dBModel2.getLocalId()));
                }
                ((ModelIdentityProvider) uVar.b).validateId(dBModel2, dBModel);
                if (z) {
                    if (dBModel != null && dBModel.getDirty()) {
                        dBModel2 = dBModel;
                    }
                    arrayList2.set(i, dBModel2);
                    i++;
                    it4 = it2;
                    zEquals = z;
                    map4 = map2;
                } else if (dBModel != null && dBModel.getDirty() && dBModel.getDeleted()) {
                    dBModel2.setDeleted(true);
                }
                if (dBModel2.getDeleted() && dBModel != null) {
                    dBModel.setDeleted(true);
                    dBModel.setDirty(false);
                    for (Relationship relationship : ((RelationshipGraph) uVar.c).getToOneRelationships(dBModel2.getModelType())) {
                        ModelIdentity toModelIdentity = relationship.getToModelIdentity(dBModel);
                        if (toModelIdentity != null) {
                            relationship.setToModelIdentity(dBModel2, toModelIdentity);
                        }
                    }
                }
                arrayList2.set(i, dBModel2);
                i++;
                it4 = it2;
                zEquals = z;
                map4 = map2;
            }
            Iterator it5 = it4;
            Map map6 = map4;
            boolean z3 = zEquals;
            map3.put(modelType2, arrayList2);
            map.put(modelType2, arrayList2);
            if (map5.get(modelType2) != null) {
                map5.put(modelType2, null);
            }
            it4 = it5;
            zEquals = z3;
            map4 = map6;
        }
        ((ExecutionRouter) this.b).f(new com.quizlet.infra.legacysyncengine.net.importer.b(this, map3, 0));
        final com.quizlet.infra.legacysyncengine.net.listeners.d dVar = (com.quizlet.infra.legacysyncengine.net.listeners.d) this.e;
        dVar.getClass();
        com.quizlet.infra.legacysyncengine.net.request.i iVar = hVar.c;
        ConcurrentHashMap concurrentHashMap = dVar.c;
        Map map7 = iVar.b;
        if (map7 != null) {
            for (final DBModel dBModel3 : map7.values()) {
                final int i2 = 0;
                concurrentHashMap.forEach(1L, new BiConsumer() { // from class: com.quizlet.infra.legacysyncengine.net.listeners.c
                    @Override // java.util.function.BiConsumer
                    public final void accept(Object obj, Object obj2) {
                        int i3 = i2;
                        IdMappedQuery idMappedQuery = (IdMappedQuery) obj;
                        d dVar2 = dVar;
                        dVar2.getClass();
                        switch (i3) {
                            case 0:
                                DBModel dBModel4 = dBModel3;
                                if (dBModel4 != null && idMappedQuery.a(dBModel4)) {
                                    dVar2.a.b.computeIfPresent(idMappedQuery, new com.quizlet.infra.legacysyncengine.c(dBModel4, 1));
                                    break;
                                }
                                break;
                            default:
                                DBModel dBModel5 = dBModel3;
                                if (dBModel5 != null && idMappedQuery.a(dBModel5)) {
                                    dVar2.a.b.computeIfPresent(idMappedQuery, new com.quizlet.infra.legacysyncengine.c(dBModel5, 1));
                                    break;
                                }
                                break;
                        }
                    }
                });
            }
        }
        Map map8 = iVar.c;
        if (map8 != null) {
            for (final DBModel dBModel4 : map8.values()) {
                final int i3 = 1;
                concurrentHashMap.forEach(1L, new BiConsumer() { // from class: com.quizlet.infra.legacysyncengine.net.listeners.c
                    @Override // java.util.function.BiConsumer
                    public final void accept(Object obj, Object obj2) {
                        int i32 = i3;
                        IdMappedQuery idMappedQuery = (IdMappedQuery) obj;
                        d dVar2 = dVar;
                        dVar2.getClass();
                        switch (i32) {
                            case 0:
                                DBModel dBModel42 = dBModel4;
                                if (dBModel42 != null && idMappedQuery.a(dBModel42)) {
                                    dVar2.a.b.computeIfPresent(idMappedQuery, new com.quizlet.infra.legacysyncengine.c(dBModel42, 1));
                                    break;
                                }
                                break;
                            default:
                                DBModel dBModel5 = dBModel4;
                                if (dBModel5 != null && idMappedQuery.a(dBModel5)) {
                                    dVar2.a.b.computeIfPresent(idMappedQuery, new com.quizlet.infra.legacysyncengine.c(dBModel5, 1));
                                    break;
                                }
                                break;
                        }
                    }
                });
            }
        }
        Iterator it6 = map.keySet().iterator();
        while (it6.hasNext()) {
            List list5 = (List) map.get((ModelType) it6.next());
            if (list5 != null) {
                concurrentHashMap.forEach(1L, new com.quizlet.infra.legacysyncengine.net.listeners.b(dVar, list5, z2));
            }
        }
        ((io.reactivex.rxjava3.subjects.r) this.i).onSuccess(map3);
    }

    public synchronized com.quizlet.quizletandroid.k s(com.snowplowanalytics.snowplow.event.a event) {
        com.quizlet.quizletandroid.k kVar;
        try {
            Intrinsics.checkNotNullParameter(event, "event");
            if (event instanceof com.snowplowanalytics.snowplow.event.a) {
                LinkedList<com.snowplowanalytics.core.statemachine.f> linkedList = new LinkedList();
                List list = (List) ((HashMap) this.d).get(event.b());
                if (list != null) {
                    linkedList.addAll(list);
                }
                List list2 = (List) ((HashMap) this.d).get("*");
                if (list2 != null) {
                    linkedList.addAll(list2);
                }
                for (com.snowplowanalytics.core.statemachine.f stateMachine : linkedList) {
                    String stateIdentifier = (String) ((HashMap) this.c).get(stateMachine);
                    com.snowplowanalytics.core.statemachine.e eVarN = stateIdentifier != null ? ((com.quizlet.quizletandroid.k) this.i).n(stateIdentifier) : null;
                    Intrinsics.checkNotNullParameter(event, "event");
                    Intrinsics.checkNotNullParameter(stateMachine, "stateMachine");
                    com.snowplowanalytics.core.statemachine.e state = new com.snowplowanalytics.core.statemachine.e();
                    state.a = event;
                    state.b = eVarN;
                    state.c = stateMachine;
                    if (stateIdentifier != null) {
                        com.quizlet.quizletandroid.k kVar2 = (com.quizlet.quizletandroid.k) this.i;
                        synchronized (kVar2) {
                            Intrinsics.checkNotNullParameter(stateIdentifier, "stateIdentifier");
                            Intrinsics.checkNotNullParameter(state, "state");
                            ((HashMap) kVar2.b).put(stateIdentifier, state);
                        }
                    }
                    state.a();
                }
            }
            com.quizlet.quizletandroid.k kVar3 = (com.quizlet.quizletandroid.k) this.i;
            synchronized (kVar3) {
                kVar = new com.quizlet.quizletandroid.k(17);
                kVar.b = new HashMap((HashMap) kVar3.b);
            }
        } catch (Throwable th) {
            throw th;
        }
        return kVar;
    }

    public LinkedHashMap t(LinkedHashMap linkedHashMap, LinkedHashMap linkedHashMap2) {
        LinkedHashMap linkedHashMap3 = new LinkedHashMap(linkedHashMap);
        for (Map.Entry entry : linkedHashMap2.entrySet()) {
            String str = (String) entry.getKey();
            String str2 = (String) entry.getValue();
            String str3 = (String) linkedHashMap3.get(str);
            C2859y7 c2859y7 = (C2859y7) ((HashMap) this.d).get(str);
            if (c2859y7 == null) {
                c2859y7 = C2859y7.b;
            }
            linkedHashMap3.put(str, c2859y7.a(str3, str2));
        }
        return linkedHashMap3;
    }

    public void u(Vp vp) {
        com.google.common.util.concurrent.e eVarC;
        synchronized (this) {
            Iterator it2 = vp.a.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    eVarC = AbstractC2025es.C(new zzdwf(3));
                    break;
                }
                InterfaceC2751vm interfaceC2751vmA = ((InterfaceC2488pg) this.d).a(vp.b, (String) it2.next());
                if (interfaceC2751vmA != null && interfaceC2751vmA.a((C1849aq) this.i, vp)) {
                    eVarC = AbstractC2025es.O(interfaceC2751vmA.b((C1849aq) this.i, vp), vp.R, TimeUnit.MILLISECONDS, (ScheduledExecutorService) this.c);
                    break;
                }
            }
        }
        ((C2195in) this.e).a((C1849aq) this.i, vp, eVarC, (C2542qr) this.f);
        eVarC.a(new Qv(0, eVarC, new C1732Mb(this, false, vp, 27)), (Xv) this.b);
    }

    public void v(LinkedHashMap linkedHashMap, A7 a7) throws Throwable {
        FileOutputStream fileOutputStream;
        Uri.Builder builderBuildUpon = Uri.parse((String) this.a).buildUpon();
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            builderBuildUpon.appendQueryParameter((String) entry.getKey(), (String) entry.getValue());
        }
        String string = builderBuildUpon.build().toString();
        if (a7 != null) {
            StringBuilder sb = new StringBuilder(string);
            String str = a7.a;
            if (!TextUtils.isEmpty(str)) {
                sb.append("&it=");
                sb.append(str);
            }
            String str2 = a7.b;
            if (!TextUtils.isEmpty(str2)) {
                sb.append("&blat=");
                sb.append(str2);
            }
            string = sb.toString();
        }
        FileOutputStream fileOutputStream2 = null;
        if (!((AtomicBoolean) this.h).get()) {
            com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
            new com.google.android.gms.ads.internal.util.t((Context) this.e, (String) this.f, string, null).R();
            return;
        }
        File file = (File) this.i;
        try {
            if (file == null) {
                com.google.android.gms.ads.internal.util.client.i.h("CsiReporter: File doesn't exist. Cannot write CSI data to file.");
                return;
            }
            try {
                fileOutputStream = new FileOutputStream(file, true);
            } catch (IOException e) {
                e = e;
            }
            try {
                fileOutputStream.write(string.getBytes());
                fileOutputStream.write(10);
                try {
                    fileOutputStream.close();
                } catch (IOException e2) {
                    com.google.android.gms.ads.internal.util.client.i.i("CsiReporter: Cannot close file: sdk_csi_data.txt.", e2);
                }
            } catch (IOException e3) {
                e = e3;
                fileOutputStream2 = fileOutputStream;
                com.google.android.gms.ads.internal.util.client.i.i("CsiReporter: Cannot write to file: sdk_csi_data.txt.", e);
                if (fileOutputStream2 != null) {
                    try {
                        fileOutputStream2.close();
                    } catch (IOException e4) {
                        com.google.android.gms.ads.internal.util.client.i.i("CsiReporter: Cannot close file: sdk_csi_data.txt.", e4);
                    }
                }
            } catch (Throwable th) {
                th = th;
                fileOutputStream2 = fileOutputStream;
                if (fileOutputStream2 != null) {
                    try {
                        fileOutputStream2.close();
                    } catch (IOException e5) {
                        com.google.android.gms.ads.internal.util.client.i.i("CsiReporter: Cannot close file: sdk_csi_data.txt.", e5);
                    }
                }
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    public s(int i) {
        switch (i) {
            case 11:
                this.b = new HashMap();
                this.c = new HashMap();
                this.d = new HashMap();
                this.e = new HashMap();
                this.f = new HashMap();
                this.g = new HashMap();
                this.a = new HashMap();
                this.h = new HashMap();
                this.i = new com.quizlet.quizletandroid.k(17);
                break;
            default:
                this.b = new ArrayBlockingQueue(100);
                this.c = new LinkedHashMap();
                this.d = new HashMap();
                this.g = new HashSet(Arrays.asList("noop", "activeViewPingSent", "viewabilityChanged", "visibilityChanged"));
                break;
        }
    }

    public s(ExecutionRouter executionRouter, DatabaseHelper databaseHelper, ModelIdentityProvider modelIdentityProvider, com.quizlet.infra.legacysyncengine.net.listeners.d dVar, androidx.compose.foundation.text.input.internal.u uVar, com.quizlet.infra.legacysyncengine.tasks.parse.h hVar, HashMap map, com.quizlet.infra.legacysyncengine.net.constants.a aVar) {
        this.b = executionRouter;
        this.c = databaseHelper;
        this.d = modelIdentityProvider;
        this.e = dVar;
        this.f = uVar;
        this.g = hVar;
        this.a = map == null ? new HashMap() : map;
        this.h = aVar;
        this.i = new io.reactivex.rxjava3.subjects.r();
    }
}
