package androidx.work.impl.model;

import android.app.Application;
import android.content.Context;
import android.content.res.Resources;
import android.database.Cursor;
import android.os.IBinder;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;
import android.widget.EditText;
import androidx.appcompat.app.L;
import androidx.camera.camera2.internal.V;
import androidx.camera.core.C0153e;
import androidx.camera.core.impl.DeferrableSurface$SurfaceClosedException;
import androidx.camera.core.impl.o0;
import androidx.camera.core.impl.q0;
import androidx.compose.foundation.lazy.layout.p0;
import androidx.compose.material3.C0676l1;
import androidx.datastore.core.InterfaceC1076h;
import androidx.work.impl.WorkDatabase_Impl;
import com.comscore.streaming.EventType;
import com.facebook.z;
import com.google.android.gms.cloudmessaging.zzd;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3744v4;
import com.google.gson.reflect.TypeToken;
import com.perimeterx.mobile_sdk.local_data.w;
import com.perimeterx.mobile_sdk.local_data.x;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.persisted.DBGroupFolder;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.features.match.data.W;
import com.quizlet.generated.enums.G1;
import com.quizlet.quizletandroid.ui.login.BaseSignupFragment;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.reflect.Constructor;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentNavigableMap;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.b0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes.dex */
public final class v implements androidx.camera.core.impl.utils.futures.c, coil3.memory.f, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    public /* synthetic */ v(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // coil3.memory.f
    public long a() {
        return ((p0) this.c).f();
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case EventType.WINDOW_STATE /* 22 */:
                Map preexistingIdMap = (Map) obj;
                Intrinsics.checkNotNullParameter(preexistingIdMap, "preexistingIdMap");
                ArrayList arrayList = (ArrayList) this.b;
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    DBGroupFolder dBGroupFolder = (DBGroupFolder) it2.next();
                    ((com.quizlet.local.ormlite.models.bookmark.a) this.c).getClass();
                    Long l = (Long) preexistingIdMap.get(new com.quizlet.data.repository.classfolder.a(dBGroupFolder.getClassId(), dBGroupFolder.getFolderId()));
                    if (l != null) {
                        dBGroupFolder.setLocalId(l.longValue());
                    }
                }
                return arrayList;
            case EventType.SUBS /* 25 */:
                List dbStudySets = (List) obj;
                Intrinsics.checkNotNullParameter(dbStudySets, "setList");
                com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) this.b;
                sVar.getClass();
                Intrinsics.checkNotNullParameter(dbStudySets, "dbStudySets");
                Set requestedIds = (Set) this.c;
                Intrinsics.checkNotNullParameter(requestedIds, "requestedIds");
                ArrayList arrayList2 = new ArrayList(C.q(dbStudySets, 10));
                Iterator it3 = dbStudySets.iterator();
                while (it3.hasNext()) {
                    arrayList2.add(Long.valueOf(((DBStudySet) it3.next()).getId()));
                }
                Set setE = b0.e(requestedIds, CollectionsKt.A0(arrayList2));
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
                bVar.c(DBStudySetFields.ID, setE, null);
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
                Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
                io.reactivex.rxjava3.internal.operators.single.g gVarG = sVar.o(aVarA).g(new com.quizlet.quizletandroid.config.d(dbStudySets, 1));
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                return gVarG;
            case 27:
                String email = (String) obj;
                Intrinsics.checkNotNullParameter(email, "email");
                BaseSignupFragment baseSignupFragment = (BaseSignupFragment) this.b;
                v vVar = baseSignupFragment.g;
                if (vVar == null) {
                    Intrinsics.m("checkEmailUseCase");
                    throw null;
                }
                io.reactivex.rxjava3.subjects.r stopToken = (io.reactivex.rxjava3.subjects.r) this.c;
                Intrinsics.checkNotNullParameter(email, "email");
                Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                return new J(((c) vVar.c).c(stopToken, new com.braze.triggers.managers.h(26, vVar, email)).m(), new com.quizlet.quizletandroid.ui.login.h(baseSignupFragment, 0), 4);
            default:
                com.quizlet.features.infra.basestudy.data.models.shareset.a shareStatus = (com.quizlet.features.infra.basestudy.data.models.shareset.a) obj;
                Intrinsics.checkNotNullParameter(shareStatus, "shareStatus");
                return new W(shareStatus, (DBStudySet) this.c, ((com.quizlet.quizletandroid.ui.studymodes.match.managers.a) this.b).b.e.getPersonId());
        }
    }

    public com.perimeterx.mobile_sdk.detections.a b(com.perimeterx.mobile_sdk.session.m session, androidx.camera.camera2.internal.compat.workaround.a aVar) {
        com.quizlet.data.interactor.set.c cVar = new com.quizlet.data.interactor.set.c(session, aVar);
        Application context = (Application) this.b;
        com.perimeterx.mobile_sdk.detections.device.a aVarB = cVar.b(context);
        androidx.compose.material.ripple.r rVarA = AbstractC3744v4.a(context);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(session, "session");
        x key = x.d;
        String appId = session.a;
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        com.perimeterx.mobile_sdk.local_data.b bVar = w.c;
        if (bVar == null) {
            Intrinsics.m("storage");
            throw null;
        }
        Integer numF = bVar.f(key, appId);
        int iIntValue = numF != null ? numF.intValue() : 0;
        int i = iIntValue + 1;
        String appId2 = session.a;
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId2, "appId");
        com.perimeterx.mobile_sdk.local_data.b bVar2 = w.c;
        if (bVar2 == null) {
            Intrinsics.m("storage");
            throw null;
        }
        bVar2.b(i, key, appId2);
        com.perimeterx.mobile_sdk.detections.a aVar2 = new com.perimeterx.mobile_sdk.detections.a(aVarB, rVarA, new C0676l1(iIntValue, (int) (new Date().getTime() - com.perimeterx.mobile_sdk.detections.usage.a.a), false), new Date());
        this.c = aVar2;
        return aVar2;
    }

    public com.google.gson.internal.n c(TypeToken typeToken) throws NoSuchMethodException, SecurityException {
        com.google.firebase.platforminfo.c cVar;
        HashMap map = (HashMap) this.b;
        Type type = typeToken.b;
        if (map.get(type) != null) {
            throw new ClassCastException();
        }
        Class cls = typeToken.a;
        if (map.get(cls) != null) {
            throw new ClassCastException();
        }
        com.google.gson.internal.n bVar = null;
        try {
            Constructor declaredConstructor = cls.getDeclaredConstructor(null);
            if (!declaredConstructor.isAccessible()) {
                ((com.google.gson.internal.reflect.b) this.c).a(declaredConstructor);
            }
            cVar = new com.google.firebase.platforminfo.c(declaredConstructor);
        } catch (NoSuchMethodException unused) {
            cVar = null;
        }
        if (cVar != null) {
            return cVar;
        }
        if (Collection.class.isAssignableFrom(cls)) {
            bVar = SortedSet.class.isAssignableFrom(cls) ? new com.google.mlkit.common.sdkinternal.b(19) : EnumSet.class.isAssignableFrom(cls) ? new L(type, 29) : Set.class.isAssignableFrom(cls) ? new com.google.mlkit.common.sdkinternal.model.a(19) : Queue.class.isAssignableFrom(cls) ? new com.onetrust.otpublishers.headless.Internal.Helper.h(19) : new com.quizlet.shared.usecase.folderstudymaterials.a(19);
        } else if (Map.class.isAssignableFrom(cls)) {
            bVar = ConcurrentNavigableMap.class.isAssignableFrom(cls) ? new com.quizlet.shared.usecase.folderstudymaterials.b(19) : ConcurrentMap.class.isAssignableFrom(cls) ? new com.google.android.material.shape.e(19) : SortedMap.class.isAssignableFrom(cls) ? new com.google.firebase.heartbeatinfo.e(19) : (!(type instanceof ParameterizedType) || String.class.isAssignableFrom(new TypeToken(((ParameterizedType) type).getActualTypeArguments()[0]).a)) ? new com.google.mlkit.common.internal.model.a(19) : new com.google.firebase.perf.logging.b(19);
        }
        return bVar != null ? bVar : new com.quizlet.data.repository.course.membership.c(cls, type);
    }

    @Override // coil3.memory.f
    public void clear() {
        ((p0) this.c).h(-1L);
    }

    public boolean d(long j) {
        return ((z) this.b).a(j, G1.SET);
    }

    public synchronized List e(String str) {
        List arrayList;
        if (!((ArrayList) this.b).contains(str)) {
            ((ArrayList) this.b).add(str);
        }
        arrayList = (List) ((HashMap) this.c).get(str);
        if (arrayList == null) {
            arrayList = new ArrayList();
            ((HashMap) this.c).put(str, arrayList);
        }
        return arrayList;
    }

    public synchronized ArrayList f(Class cls, Class cls2) {
        ArrayList arrayList;
        arrayList = new ArrayList();
        Iterator it2 = ((ArrayList) this.b).iterator();
        while (it2.hasNext()) {
            List<com.bumptech.glide.provider.c> list = (List) ((HashMap) this.c).get((String) it2.next());
            if (list != null) {
                for (com.bumptech.glide.provider.c cVar : list) {
                    if ((cVar.a.isAssignableFrom(cls) && cls2.isAssignableFrom(cVar.b)) && !arrayList.contains(cVar.b)) {
                        arrayList.add(cVar.b);
                    }
                }
            }
        }
        return arrayList;
    }

    public ArrayList g(String str) {
        androidx.room.u uVarA = androidx.room.u.a(1, "SELECT DISTINCT tag FROM worktag WHERE work_spec_id=?");
        uVarA.g(1, str);
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.b;
        workDatabase_Impl.b();
        Cursor cursorN = W1.N(workDatabase_Impl, uVarA, false);
        try {
            ArrayList arrayList = new ArrayList(cursorN.getCount());
            while (cursorN.moveToNext()) {
                arrayList.add(cursorN.getString(0));
            }
            return arrayList;
        } finally {
            cursorN.close();
            uVarA.i();
        }
    }

    @Override // coil3.memory.f
    public boolean h(coil3.memory.a aVar) {
        p0 p0Var = (p0) this.c;
        Object objRemove = ((LinkedHashMap) p0Var.c).remove(aVar);
        if (objRemove != null) {
            p0Var.b = p0Var.f() - p0Var.g(aVar, objRemove);
            p0Var.e(aVar, objRemove, null);
        }
        return objRemove != null;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object i(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.quizletandroid.interactor.r
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.quizletandroid.interactor.r r0 = (com.quizlet.quizletandroid.interactor.r) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.interactor.r r0 = new com.quizlet.quizletandroid.interactor.r
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.work.impl.model.v r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L44
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.j = r4
            r0.m = r3
            java.lang.Object r5 = r4.b
            androidx.work.impl.model.e r5 = (androidx.work.impl.model.e) r5
            java.lang.Object r5 = r5.l(r0)
            if (r5 != r1) goto L43
            return r1
        L43:
            r0 = r4
        L44:
            java.lang.Boolean r5 = (java.lang.Boolean) r5
            boolean r5 = r5.booleanValue()
            if (r5 == 0) goto L5b
            java.lang.Object r5 = r0.c
            com.quizlet.data.connectivity.a r5 = (com.quizlet.data.connectivity.a) r5
            com.quizlet.remote.connectivity.b r5 = (com.quizlet.remote.connectivity.b) r5
            com.quizlet.data.connectivity.b r5 = r5.a()
            boolean r5 = r5.a
            if (r5 == 0) goto L5b
            goto L5c
        L5b:
            r3 = 0
        L5c:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r3)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.v.i(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x0074, code lost:
    
        if (r7 == r1) goto L27;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(kotlin.coroutines.jvm.internal.c r7) {
        /*
            r6 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.upsell.a
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.upsell.a r0 = (com.quizlet.data.interactor.upsell.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.upsell.a r0 = new com.quizlet.data.interactor.upsell.a
            r0.<init>(r6, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L78
        L2a:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L32:
            androidx.work.impl.model.v r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4f
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r6
            r0.m = r4
            java.lang.Object r7 = r6.c
            com.quizlet.remote.model.notes.e r7 = (com.quizlet.remote.model.notes.e) r7
            java.lang.Object r2 = r7.e
            java.lang.Enum r2 = (java.lang.Enum) r2
            java.lang.Enum r7 = r7.k(r2)
            if (r7 != r1) goto L4e
            goto L76
        L4e:
            r2 = r6
        L4f:
            com.quizlet.featuregate.contracts.enums.c r5 = com.quizlet.featuregate.contracts.enums.c.b
            if (r7 != r5) goto L77
            java.lang.Object r7 = r2.b
            com.quizlet.data.interactor.course.a r7 = (com.quizlet.data.interactor.course.a) r7
            r2 = 0
            r0.j = r2
            r0.m = r3
            java.lang.String r3 = "show_delayed_upsell"
            androidx.datastore.preferences.core.f r3 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r3)
            com.quizlet.local.datastore.preferences.i0 r5 = new com.quizlet.local.datastore.preferences.i0
            r5.<init>(r3, r2)
            java.lang.Object r7 = r7.b
            androidx.datastore.core.h r7 = (androidx.datastore.core.InterfaceC1076h) r7
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_barcode.S6.d(r7, r5, r0)
            if (r7 != r1) goto L72
            goto L74
        L72:
            kotlin.Unit r7 = kotlin.Unit.a
        L74:
            if (r7 != r1) goto L78
        L76:
            return r1
        L77:
            r4 = 0
        L78:
            java.lang.Boolean r7 = java.lang.Boolean.valueOf(r4)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.v.j(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // coil3.memory.f
    public void k(coil3.memory.a aVar, coil3.j jVar, Map map, long j) {
        p0 p0Var = (p0) this.c;
        long j2 = p0Var.a;
        LinkedHashMap linkedHashMap = (LinkedHashMap) p0Var.c;
        if (j > j2) {
            Object objRemove = linkedHashMap.remove(aVar);
            if (objRemove != null) {
                p0Var.b = p0Var.f() - p0Var.g(aVar, objRemove);
                p0Var.e(aVar, objRemove, null);
            }
            ((com.android.billingclient.api.s) this.b).m(aVar, jVar, map, j);
            return;
        }
        coil3.memory.d dVar = new coil3.memory.d(jVar, map, j);
        Object objPut = linkedHashMap.put(aVar, dVar);
        p0Var.b = p0Var.g(aVar, dVar) + p0Var.f();
        if (objPut != null) {
            p0Var.b = p0Var.f() - p0Var.g(aVar, objPut);
            p0Var.e(aVar, objPut, dVar);
        }
        p0Var.h(p0Var.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object l(kotlin.coroutines.jvm.internal.c r7) {
        /*
            r6 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.upsell.b
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.upsell.b r0 = (com.quizlet.data.interactor.upsell.b) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.data.interactor.upsell.b r0 = new com.quizlet.data.interactor.upsell.b
            r0.<init>(r6, r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L34
            if (r2 != r3) goto L2c
            boolean r0 = r0.k
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L7a
        L2c:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L34:
            androidx.work.impl.model.v r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4d
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r6
            r0.n = r4
            java.lang.Object r7 = r6.b
            com.quizlet.data.interactor.course.a r7 = (com.quizlet.data.interactor.course.a) r7
            java.lang.Object r7 = r7.k(r0)
            if (r7 != r1) goto L4c
            goto L78
        L4c:
            r2 = r6
        L4d:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            java.lang.Object r2 = r2.b
            com.quizlet.data.interactor.course.a r2 = (com.quizlet.data.interactor.course.a) r2
            r4 = 0
            r0.j = r4
            r0.k = r7
            r0.n = r3
            java.lang.String r3 = "show_delayed_upsell"
            androidx.datastore.preferences.core.f r3 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r3)
            com.quizlet.local.datastore.preferences.h0 r5 = new com.quizlet.local.datastore.preferences.h0
            r5.<init>(r3, r4)
            java.lang.Object r2 = r2.b
            androidx.datastore.core.h r2 = (androidx.datastore.core.InterfaceC1076h) r2
            java.lang.Object r0 = com.google.android.gms.internal.mlkit_vision_barcode.S6.d(r2, r5, r0)
            if (r0 != r1) goto L74
            goto L76
        L74:
            kotlin.Unit r0 = kotlin.Unit.a
        L76:
            if (r0 != r1) goto L79
        L78:
            return r1
        L79:
            r0 = r7
        L7a:
            java.lang.Boolean r7 = java.lang.Boolean.valueOf(r0)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.v.l(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // coil3.memory.f
    public coil3.memory.b o(coil3.memory.a aVar) {
        coil3.memory.d dVar = (coil3.memory.d) ((LinkedHashMap) ((p0) this.c).c).get(aVar);
        if (dVar != null) {
            return new coil3.memory.b(dVar.a, dVar.b);
        }
        return null;
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        q0 q0Var;
        if (!(th instanceof DeferrableSurface$SurfaceClosedException)) {
            if (th instanceof CancellationException) {
                ((androidx.camera.camera2.internal.C) this.c).t("Unable to configure camera cancelled");
                return;
            }
            if (((androidx.camera.camera2.internal.C) this.c).H == 9) {
                ((androidx.camera.camera2.internal.C) this.c).E(9, new C0153e(4, th), true);
            }
            AbstractC3053s1.d("Camera2CameraImpl", "Unable to configure camera " + ((androidx.camera.camera2.internal.C) this.c), th);
            androidx.camera.camera2.internal.C c = (androidx.camera.camera2.internal.C) this.c;
            if (c.l == ((V) this.b)) {
                c.D();
                return;
            }
            return;
        }
        androidx.camera.camera2.internal.C c2 = (androidx.camera.camera2.internal.C) this.c;
        androidx.camera.core.impl.J j = ((DeferrableSurface$SurfaceClosedException) th).a;
        Iterator it2 = c2.a.b().iterator();
        while (true) {
            if (!it2.hasNext()) {
                q0Var = null;
                break;
            } else {
                q0Var = (q0) it2.next();
                if (q0Var.b().contains(j)) {
                    break;
                }
            }
        }
        if (q0Var != null) {
            androidx.camera.camera2.internal.C c3 = (androidx.camera.camera2.internal.C) this.c;
            c3.getClass();
            androidx.camera.core.impl.utils.executor.e eVarE = T.e();
            o0 o0Var = q0Var.f;
            if (o0Var != null) {
                new Throwable();
                c3.t("Posting surface closed");
                eVarE.execute(new androidx.activity.r(5, o0Var, q0Var));
            }
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        androidx.camera.camera2.internal.C c = (androidx.camera.camera2.internal.C) this.c;
        if (c.p.b == 2 && c.H == 9) {
            ((androidx.camera.camera2.internal.C) this.c).F(10);
        }
    }

    @Override // coil3.memory.f
    public void p(long j) {
        ((p0) this.c).h(j);
    }

    public String toString() {
        switch (this.a) {
            case 13:
                return ((HashMap) this.b).toString();
            default:
                return super.toString();
        }
    }

    public /* synthetic */ v(int i, boolean z) {
        this.a = i;
    }

    public v(Application context) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(context, "context");
        this.b = context;
    }

    public v(IBinder iBinder) throws RemoteException {
        this.a = 9;
        String interfaceDescriptor = iBinder.getInterfaceDescriptor();
        if (Objects.equals(interfaceDescriptor, "android.os.IMessenger")) {
            this.b = new Messenger(iBinder);
            this.c = null;
        } else if (Objects.equals(interfaceDescriptor, "com.google.android.gms.iid.IMessengerCompat")) {
            this.c = new zzd(iBinder);
            this.b = null;
        } else {
            Log.w("MessengerIpcClient", "Invalid interface descriptor: ".concat(String.valueOf(interfaceDescriptor)));
            throw new RemoteException();
        }
    }

    public v(z setInSelectedTermsModeCache, com.quizlet.data.repository.explanations.textbook.a termAndSelectedTermRepository) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(setInSelectedTermsModeCache, "setInSelectedTermsModeCache");
        Intrinsics.checkNotNullParameter(termAndSelectedTermRepository, "termAndSelectedTermRepository");
        this.b = setInSelectedTermsModeCache;
        this.c = termAndSelectedTermRepository;
    }

    public v(e practiceTestViewAndTakeFeature, com.quizlet.data.connectivity.a networkStatus) {
        this.a = 26;
        Intrinsics.checkNotNullParameter(practiceTestViewAndTakeFeature, "practiceTestViewAndTakeFeature");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        this.b = practiceTestViewAndTakeFeature;
        this.c = networkStatus;
    }

    public v(com.quizlet.data.interactor.course.a preferencesRepository, com.quizlet.remote.model.notes.e onboardingELLFeature) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(preferencesRepository, "preferencesRepository");
        Intrinsics.checkNotNullParameter(onboardingELLFeature, "onboardingELLFeature");
        this.b = preferencesRepository;
        this.c = onboardingELLFeature;
    }

    public v(com.quizlet.local.ormlite.models.studysetwithcreator.a studySetWithCreatorLocalDataStore, com.quizlet.remote.model.union.studysetwithcreator.c studySetWithCreatorRemoteDataStore) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(studySetWithCreatorLocalDataStore, "studySetWithCreatorLocalDataStore");
        Intrinsics.checkNotNullParameter(studySetWithCreatorRemoteDataStore, "studySetWithCreatorRemoteDataStore");
        this.b = studySetWithCreatorLocalDataStore;
        this.c = studySetWithCreatorRemoteDataStore;
    }

    public v(InterfaceC1076h preferences) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(preferences, "preferences");
        this.b = preferences;
        this.c = new com.quizlet.features.flashcards.helpers.d(preferences.getData(), 0);
    }

    public v(com.quizlet.data.repository.login.a signUpValidationRepository, c dispatcher) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(signUpValidationRepository, "signUpValidationRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = signUpValidationRepository;
        this.c = dispatcher;
    }

    public v(com.quizlet.data.repository.classmembership.c repository, c dispatcher) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = repository;
        this.c = dispatcher;
    }

    public v(c dataSource, com.quizlet.quizletandroid.ui.login.h explanationsSearchResultMapper, com.quizlet.quizletandroid.ui.folder.logging.a pagingInfoMapper) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(explanationsSearchResultMapper, "explanationsSearchResultMapper");
        Intrinsics.checkNotNullParameter(pagingInfoMapper, "pagingInfoMapper");
        this.b = dataSource;
        this.c = explanationsSearchResultMapper;
    }

    public v(com.quizlet.data.repository.folderwithcreator.e repository, AbstractC5040y ioDispatcher) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = repository;
        this.c = ioDispatcher;
    }

    public v(DatabaseHelper database, AbstractC5040y dispatcher) {
        this.a = 23;
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = database;
        this.c = dispatcher;
    }

    public v(int i) {
        this.a = i;
        switch (i) {
            case 8:
                this.b = new ArrayList();
                this.c = new HashMap();
                break;
            default:
                this.b = new androidx.compose.runtime.collection.b(new Reference[16]);
                this.c = new ReferenceQueue();
                break;
        }
    }

    public v(WorkDatabase_Impl database) {
        this.a = 0;
        this.b = database;
        Intrinsics.checkNotNullParameter(database, "database");
        this.c = new b(database, 6);
        new h(database, 20);
    }

    public v(HashMap map) {
        this.a = 13;
        this.c = com.google.gson.internal.reflect.b.a;
        this.b = map;
    }

    public v(long j, com.android.billingclient.api.s sVar) {
        this.a = 6;
        this.b = sVar;
        p0 p0Var = new p0();
        p0Var.d = this;
        p0Var.a = j;
        p0Var.c = new LinkedHashMap(0, 0.75f, true);
        if (j > 0) {
            this.c = p0Var;
            return;
        }
        throw new IllegalArgumentException("maxSize <= 0");
    }

    public v(com.google.firebase.crashlytics.internal.c cVar) throws Resources.NotFoundException, IOException {
        this.a = 12;
        int iD = com.google.firebase.crashlytics.internal.common.f.d(cVar.a, "com.google.firebase.crashlytics.unity_version", "string");
        Context context = cVar.a;
        if (iD != 0) {
            this.b = "Unity";
            this.c = context.getResources().getString(iD);
            Log.isLoggable("FirebaseCrashlytics", 2);
            return;
        }
        if (context.getAssets() != null) {
            try {
                InputStream inputStreamOpen = context.getAssets().open("flutter_assets/NOTICES.Z");
                if (inputStreamOpen != null) {
                    inputStreamOpen.close();
                }
                this.b = "Flutter";
                this.c = null;
                Log.isLoggable("FirebaseCrashlytics", 2);
                return;
            } catch (IOException unused) {
            }
        }
        this.b = null;
        this.c = null;
    }

    public v(EditText editText) {
        this.a = 5;
        this.b = editText;
        androidx.emoji2.viewsintegration.g gVar = new androidx.emoji2.viewsintegration.g(editText);
        this.c = gVar;
        editText.addTextChangedListener(gVar);
        if (androidx.emoji2.viewsintegration.a.b == null) {
            synchronized (androidx.emoji2.viewsintegration.a.a) {
                try {
                    if (androidx.emoji2.viewsintegration.a.b == null) {
                        androidx.emoji2.viewsintegration.a aVar = new androidx.emoji2.viewsintegration.a();
                        try {
                            androidx.emoji2.viewsintegration.a.c = Class.forName("android.text.DynamicLayout$ChangeWatcher", false, androidx.emoji2.viewsintegration.a.class.getClassLoader());
                        } catch (Throwable unused) {
                        }
                        androidx.emoji2.viewsintegration.a.b = aVar;
                    }
                } finally {
                }
            }
        }
        editText.setEditableFactory(androidx.emoji2.viewsintegration.a.b);
    }

    public v(androidx.camera.camera2.internal.C c, V v) {
        this.a = 1;
        this.c = c;
        this.b = v;
    }
}
