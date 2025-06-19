package com.quizlet.infra.legacysyncengine.net.listeners;

import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import com.quizlet.infra.legacysyncengine.e;
import com.quizlet.infra.legacysyncengine.net.g;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements BiConsumer {
    public final /* synthetic */ d a;
    public final /* synthetic */ List b;
    public final /* synthetic */ boolean c;

    public /* synthetic */ b(d dVar, List list, boolean z) {
        this.a = dVar;
        this.b = list;
        this.c = z;
    }

    @Override // java.util.function.BiConsumer
    public final void accept(Object obj, Object obj2) {
        final boolean z;
        DBModel dBModel;
        IdMappedQuery idMappedQuery = (IdMappedQuery) obj;
        List list = (List) obj2;
        final e eVar = this.a.a;
        ConcurrentHashMap concurrentHashMap = eVar.b;
        g gVar = (g) concurrentHashMap.get(idMappedQuery);
        List<DBModel> arrayList = gVar != null ? gVar.a : null;
        if (arrayList != null) {
            arrayList = new ArrayList(arrayList);
        }
        final ArrayList arrayList2 = new ArrayList();
        ArrayList arrayList3 = new ArrayList();
        Iterator it2 = this.b.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            z = this.c;
            if (!zHasNext) {
                break;
            }
            DBModel dBModel2 = (DBModel) it2.next();
            if (arrayList == null || arrayList.isEmpty() || !dBModel2.getModelType().equals(idMappedQuery.getModelType())) {
                dBModel = null;
            } else {
                ModelIdentity identity = dBModel2.getIdentity();
                for (DBModel dBModel3 : arrayList) {
                    if (dBModel3 != null && (!dBModel3.getDirty() || z)) {
                        if (dBModel3.getLocalId() == dBModel2.getLocalId() || identity.equals(dBModel3.getIdentity())) {
                            dBModel = dBModel3;
                            break;
                        }
                    }
                }
                dBModel = null;
            }
            if (dBModel != null && dBModel2 != null) {
                for (Relationship relationship : eVar.a.getToOneRelationships(dBModel.getModelType())) {
                    DBModel model = relationship.getModel(dBModel);
                    boolean z2 = !relationship.isRequired() && relationship.getToModelIdentity(dBModel2) == null;
                    if (model != null && !z2) {
                        relationship.setModel(dBModel2, model);
                    }
                }
            }
            if (idMappedQuery.a(dBModel2)) {
                arrayList2.add(dBModel2);
            } else if (dBModel != null) {
                arrayList3.add(dBModel);
            }
        }
        boolean z3 = arrayList2.size() > 0 || arrayList3.size() > 0;
        if (arrayList3.size() > 0) {
            concurrentHashMap.computeIfPresent(idMappedQuery, new com.quizlet.infra.legacysyncengine.c(arrayList3, 0));
        }
        if (z3) {
            final Map mapIdentityMap = ModelIdentityProvider.identityMap(arrayList2);
            concurrentHashMap.computeIfPresent(idMappedQuery, new BiFunction() { // from class: com.quizlet.infra.legacysyncengine.d
                /* JADX WARN: Removed duplicated region for block: B:16:0x005a  */
                @Override // java.util.function.BiFunction
                /*
                    Code decompiled incorrectly, please refer to instructions dump.
                    To view partially-correct add '--show-bad-code' argument
                */
                public final java.lang.Object apply(java.lang.Object r8, java.lang.Object r9) {
                    /*
                        r7 = this;
                        com.quizlet.db.data.orm.query.IdMappedQuery r8 = (com.quizlet.db.data.orm.query.IdMappedQuery) r8
                        com.quizlet.infra.legacysyncengine.net.g r9 = (com.quizlet.infra.legacysyncengine.net.g) r9
                        com.quizlet.infra.legacysyncengine.e r8 = r1
                        r8.getClass()
                        java.util.List r8 = r9.a
                        if (r8 != 0) goto L12
                        java.util.ArrayList r8 = new java.util.ArrayList
                        r8.<init>()
                    L12:
                        java.util.ArrayList r0 = r2
                        androidx.collection.q r0 = com.quizlet.db.data.models.identity.ModelIdentityProvider.localIdMap(r0)
                        java.util.ArrayList r1 = new java.util.ArrayList
                        r1.<init>()
                        r2 = 0
                    L1e:
                        int r3 = r8.size()
                        java.util.Map r4 = r4
                        if (r2 >= r3) goto L7f
                        java.lang.Object r3 = r8.get(r2)
                        com.quizlet.db.data.models.base.DBModel r3 = (com.quizlet.db.data.models.base.DBModel) r3
                        boolean r5 = r4.isEmpty()
                        if (r5 != 0) goto L5a
                        com.quizlet.db.data.models.identity.ModelIdentity r5 = r3.getIdentity()
                        boolean r6 = r5.hasServerIdentity()
                        if (r6 == 0) goto L43
                        java.lang.Object r4 = r4.remove(r5)
                        com.quizlet.db.data.models.base.DBModel r4 = (com.quizlet.db.data.models.base.DBModel) r4
                        goto L5b
                    L43:
                        long r5 = r3.getLocalId()
                        java.lang.Object r5 = r0.c(r5)
                        com.quizlet.db.data.models.base.DBModel r5 = (com.quizlet.db.data.models.base.DBModel) r5
                        if (r5 == 0) goto L5a
                        com.quizlet.db.data.models.identity.ModelIdentity r5 = r5.getIdentity()
                        java.lang.Object r4 = r4.remove(r5)
                        com.quizlet.db.data.models.base.DBModel r4 = (com.quizlet.db.data.models.base.DBModel) r4
                        goto L5b
                    L5a:
                        r4 = 0
                    L5b:
                        if (r4 != 0) goto L5e
                        goto L7c
                    L5e:
                        boolean r5 = r3
                        if (r5 != 0) goto L6f
                        boolean r5 = r3.getDirty()
                        if (r5 == 0) goto L6f
                        boolean r5 = r4.getDirty()
                        if (r5 != 0) goto L6f
                        goto L7c
                    L6f:
                        boolean r5 = r4.getDeleted()
                        if (r5 == 0) goto L79
                        r1.add(r3)
                        goto L7c
                    L79:
                        r8.set(r2, r4)
                    L7c:
                        int r2 = r2 + 1
                        goto L1e
                    L7f:
                        r8.removeAll(r1)
                        java.util.Collection r0 = r4.values()
                        java.util.Iterator r0 = r0.iterator()
                    L8a:
                        boolean r1 = r0.hasNext()
                        if (r1 == 0) goto La0
                        java.lang.Object r1 = r0.next()
                        com.quizlet.db.data.models.base.DBModel r1 = (com.quizlet.db.data.models.base.DBModel) r1
                        boolean r2 = r1.getDeleted()
                        if (r2 != 0) goto L8a
                        r8.add(r1)
                        goto L8a
                    La0:
                        com.quizlet.infra.legacysyncengine.net.g r0 = new com.quizlet.infra.legacysyncengine.net.g
                        java.util.concurrent.atomic.AtomicInteger r9 = r9.b
                        int r9 = r9.get()
                        r0.<init>(r8, r9)
                        return r0
                    */
                    throw new UnsupportedOperationException("Method not decompiled: com.quizlet.infra.legacysyncengine.d.apply(java.lang.Object, java.lang.Object):java.lang.Object");
                }
            });
            concurrentHashMap.computeIfPresent(idMappedQuery, new com.quizlet.infra.legacysyncengine.b(3));
        }
        if (z3) {
            d.a(eVar.a(idMappedQuery), list);
        }
    }
}
