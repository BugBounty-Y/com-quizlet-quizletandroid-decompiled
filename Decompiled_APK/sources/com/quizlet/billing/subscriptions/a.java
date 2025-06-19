package com.quizlet.billing.subscriptions;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3525r4;
import com.google.android.material.internal.q;
import com.quizlet.db.data.models.identity.ServerIdAssignmentEvent;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import com.quizlet.eventlogger.EventLogBuilder;
import com.quizlet.eventlogger.EventLogUploader;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.infra.legacysyncengine.datasources.p;
import com.quizlet.quizletandroid.ui.base.DataSourceRecyclerViewFragment;
import com.quizlet.quizletandroid.ui.group.addclassset.AddClassSetActivity;
import com.quizlet.quizletandroid.ui.group.addclassset.AddToClassSetListFragment;
import com.quizlet.quizletandroid.ui.profile.UserSetListFragment;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                com.quizlet.data.repository.achievements.h hVar = (com.quizlet.data.repository.achievements.h) this.b;
                Throwable error = ((b) obj).b;
                boolean z = error != null;
                EventLogger eventLogger = ((com.quizlet.features.emailconfirmation.logging.a) hVar.d).a;
                if (!z) {
                    eventLogger.D("upgrade_success_sync_to_api");
                    return;
                } else {
                    Intrinsics.checkNotNullParameter(error, "error");
                    eventLogger.E("upgrade_error_sync_to_api", error.getMessage());
                    return;
                }
            case 1:
                ((io.reactivex.rxjava3.disposables.a) this.b).b((io.reactivex.rxjava3.disposables.b) obj);
                return;
            case 2:
                EventLogBuilder.b((EventLogBuilder) this.b, (com.quizlet.data.connectivity.b) obj);
                return;
            case 3:
                ((EventLogUploader) this.b).g((EventLogUploader.LogUploadResult) obj);
                return;
            case 4:
                com.quizlet.features.infra.legacyadapter.e eVar = (com.quizlet.features.infra.legacyadapter.e) this.b;
                int itemCount = eVar.getItemCount();
                for (int i = 0; i < itemCount; i++) {
                    eVar.notifyItemChanged(i, "UPDATE_OFFLINE_PAYLOAD");
                }
                return;
            case 5:
                com.quizlet.infra.legacysyncengine.datasources.h hVar2 = (com.quizlet.infra.legacysyncengine.datasources.h) this.b;
                hVar2.d = (Set) obj;
                hVar2.c();
                return;
            case 6:
                p pVar = (p) this.b;
                pVar.getClass();
                pVar.g = new HashSet(AbstractC3525r4.e(new ArrayList(AbstractC3508o4.a((List) obj, new com.quizlet.infra.legacysyncengine.datasources.g(1))), new com.quizlet.baserecyclerview.decoration.a(17)));
                pVar.c();
                return;
            case 7:
                p pVar2 = (p) this.b;
                pVar2.getClass();
                pVar2.g = new HashSet(AbstractC3525r4.e((List) obj, new com.quizlet.baserecyclerview.decoration.a(26)));
                pVar2.c();
                return;
            case 8:
                com.quizlet.infra.legacysyncengine.net.listeners.d dVar = (com.quizlet.infra.legacysyncengine.net.listeners.d) this.b;
                dVar.getClass();
                if (((ServerIdAssignmentEvent) obj).serverId == null) {
                    return;
                }
                for (Map.Entry<IdMappedQuery, IdMappedQuery> entry : dVar.b.remapQueriesForServerIdAssignment(dVar.c.keySet()).entrySet()) {
                    IdMappedQuery key = entry.getKey();
                    IdMappedQuery value = entry.getValue();
                    com.quizlet.infra.legacysyncengine.e eVar2 = dVar.a;
                    eVar2.getClass();
                    if (key.equals(value)) {
                        timber.log.c.a.o("Transferring equal queries: %s and %s", key, value);
                    }
                    synchronized (eVar2.b) {
                        com.quizlet.infra.legacysyncengine.net.g gVar = (com.quizlet.infra.legacysyncengine.net.g) eVar2.b.get(key);
                        eVar2.b.remove(key);
                        eVar2.b.put(value, gVar);
                    }
                    synchronized (dVar.c) {
                        ConcurrentHashMap concurrentHashMap = dVar.c;
                        concurrentHashMap.put(value, (List) concurrentHashMap.get(key));
                        dVar.c.remove(key);
                    }
                }
                return;
            case 9:
                com.quizlet.data.repository.classfolder.e eVar3 = (com.quizlet.data.repository.classfolder.e) this.b;
                com.quizlet.infra.legacysyncengine.net.listeners.d dVar2 = (com.quizlet.infra.legacysyncengine.net.listeners.d) eVar3.c;
                dVar2.a.b.compute(dVar2.b.convertStaleLocalIds((IdMappedQuery) eVar3.b), new com.quizlet.infra.legacysyncengine.b(1));
                return;
            case 10:
                ((io.reactivex.rxjava3.subjects.p) this.b).b((com.quizlet.infra.legacysyncengine.net.request.c) obj);
                return;
            case 11:
                com.quizlet.infra.legacysyncengine.net.request.c cVar = (com.quizlet.infra.legacysyncengine.net.request.c) obj;
                DataSourceRecyclerViewFragment dataSourceRecyclerViewFragment = (DataSourceRecyclerViewFragment) this.b;
                boolean z2 = false;
                if (dataSourceRecyclerViewFragment.isAdded()) {
                    dataSourceRecyclerViewFragment.l.c(false);
                }
                q qVar = dataSourceRecyclerViewFragment.l;
                if (cVar.b() && dataSourceRecyclerViewFragment.X()) {
                    z2 = true;
                }
                qVar.c = z2;
                qVar.a();
                return;
            case 12:
                ((AddClassSetActivity) this.b).u = (List) obj;
                return;
            case 13:
                ArrayList arrayList = ((AddToClassSetListFragment) this.b).t;
                arrayList.clear();
                arrayList.addAll((List) obj);
                return;
            default:
                ((UserSetListFragment) this.b).I((io.reactivex.rxjava3.disposables.b) obj);
                return;
        }
    }
}
