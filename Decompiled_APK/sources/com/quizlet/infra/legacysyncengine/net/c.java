package com.quizlet.infra.legacysyncengine.net;

import android.content.ComponentCallbacks2;
import android.content.res.Configuration;
import androidx.camera.camera2.internal.T;
import androidx.compose.ui.node.V;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3537t4;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import com.quizlet.features.setpage.viewmodel.C4430d;
import com.quizlet.infra.legacysyncengine.models.identity.QueryIdFieldChangeMapper;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.internal.operators.observable.B;
import io.reactivex.rxjava3.internal.operators.observable.C;
import io.reactivex.rxjava3.internal.operators.observable.E;
import io.reactivex.rxjava3.subjects.p;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;

/* loaded from: classes3.dex */
public final class c implements ComponentCallbacks2 {
    public static final Set e = Collections.unmodifiableSet(AbstractC3537t4.g(b.a, b.b));
    public final com.quizlet.infra.legacysyncengine.net.request.f a;
    public final com.quizlet.infra.legacysyncengine.net.listeners.d b;
    public final s c;
    public final QueryIdFieldChangeMapper d;

    public c(com.quizlet.infra.legacysyncengine.net.request.f fVar, com.quizlet.infra.legacysyncengine.net.listeners.d dVar, s sVar, QueryIdFieldChangeMapper queryIdFieldChangeMapper) {
        this.a = fVar;
        this.b = dVar;
        this.c = sVar;
        this.d = queryIdFieldChangeMapper;
    }

    public final void a(com.quizlet.infra.legacysyncengine.orm.query.a aVar, com.quizlet.infra.legacysyncengine.a aVar2) {
        com.quizlet.infra.legacysyncengine.net.listeners.d dVar = this.b;
        dVar.c.computeIfPresent(dVar.b.convertStaleLocalIds(aVar), new com.quizlet.infra.legacysyncengine.net.listeners.a(dVar, aVar2, 1));
    }

    public final io.reactivex.rxjava3.internal.operators.flowable.b b(com.quizlet.infra.legacysyncengine.orm.query.a aVar, b bVar) {
        return new io.reactivex.rxjava3.internal.operators.flowable.b(new T(this, aVar, bVar, 20), 3);
    }

    public final p c(com.quizlet.infra.legacysyncengine.orm.query.a aVar, Set set) {
        i iVarM;
        boolean zContains = set.contains(b.a);
        i iVarI = E.a;
        if (zContains) {
            iVarM = this.c.h(this.d.convertStaleLocalIds(aVar)).e().x(16).m();
        } else {
            iVarM = iVarI;
        }
        if (set.contains(b.b)) {
            com.quizlet.infra.legacysyncengine.net.request.f fVar = this.a;
            QueryIdFieldChangeMapper queryIdFieldChangeMapper = fVar.a;
            IdMappedQuery idMappedQueryConvertStaleLocalIds = queryIdFieldChangeMapper.convertStaleLocalIds(aVar);
            i iVar = (i) fVar.c.get(idMappedQueryConvertStaleLocalIds);
            if (iVar != null) {
                iVarI = iVar;
            } else {
                IdMappedQuery idMappedQueryConvertStaleLocalIds2 = queryIdFieldChangeMapper.convertStaleLocalIds(idMappedQueryConvertStaleLocalIds);
                V v = fVar.b;
                com.quizlet.data.repository.classfolder.e eVar = new com.quizlet.data.repository.classfolder.e(idMappedQueryConvertStaleLocalIds2, (com.quizlet.infra.legacysyncengine.net.listeners.d) v.b, v, 13);
                p pVarZ = p.z();
                i iVarK = eVar.k();
                com.quizlet.infra.legacysyncengine.net.request.e eVar2 = new com.quizlet.infra.legacysyncengine.net.request.e(fVar, idMappedQueryConvertStaleLocalIds2, pVarZ, 0);
                io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
                C c = new C(iVarK, eVar2, bVar);
                com.quizlet.billing.subscriptions.a aVar2 = new com.quizlet.billing.subscriptions.a(pVarZ, 10);
                com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
                iVarI = new B(new B(c, aVar2, gVar, bVar, bVar), gVar, gVar, new com.quizlet.eventlogger.e(pVarZ, 15), bVar).i(new C4430d(2, fVar, idMappedQueryConvertStaleLocalIds2));
            }
        }
        p pVarZ2 = p.z();
        iVarM.u(new a(this, aVar, set, pVarZ2, 0), new com.quizlet.billing.subscriptions.c(2), new C4430d(1, iVarI, pVarZ2));
        return pVarZ2;
    }

    public final ArrayList d(com.quizlet.infra.legacysyncengine.orm.query.a aVar) {
        com.quizlet.infra.legacysyncengine.net.listeners.d dVar = this.b;
        return dVar.a.a(dVar.b.convertStaleLocalIds(aVar));
    }

    public final void e(com.quizlet.infra.legacysyncengine.orm.query.a aVar, com.quizlet.infra.legacysyncengine.a aVar2) {
        com.quizlet.infra.legacysyncengine.net.listeners.d dVar = this.b;
        dVar.b(aVar, aVar2);
        ArrayList arrayListA = dVar.a.a(dVar.b.convertStaleLocalIds(aVar));
        ArrayList arrayList = new ArrayList();
        arrayList.add(aVar2);
        com.quizlet.infra.legacysyncengine.net.listeners.d.a(arrayListA, arrayList);
    }

    @Override // android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
    }

    @Override // android.content.ComponentCallbacks
    public final void onLowMemory() {
    }

    @Override // android.content.ComponentCallbacks2
    public final void onTrimMemory(int i) {
        if (i == 15 || i >= 40) {
            com.quizlet.infra.legacysyncengine.net.listeners.d dVar = this.b;
            dVar.c.clear();
            dVar.a.b.clear();
            timber.log.c.a.g("All listeners aborted due to onTrimMemory(%d)", Integer.valueOf(i));
        }
    }
}
