package com.quizlet.db.data.models.identity;

import android.database.sqlite.SQLiteConstraintException;
import androidx.collection.C0219q;
import androidx.work.impl.A;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.DeleteBuilder;
import com.j256.ormlite.stmt.UpdateBuilder;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.base.RelationshipGraph;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.net.localid.LocalIdMap;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.db.data.orm.Relationship;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.flowable.b;
import io.reactivex.rxjava3.internal.operators.single.k;
import io.reactivex.rxjava3.schedulers.e;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import kotlin.Metadata;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.M;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.collections.Z;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import timber.log.a;
import timber.log.c;

@Metadata
/* loaded from: classes2.dex */
public final class ModelIdentityProvider {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private final DatabaseHelper database;

    @NotNull
    private final ExecutionRouter executionRouter;

    @NotNull
    private final Map<ModelType<? extends DBModel>, AtomicLong> localIdAutoDecrementMap;

    @NotNull
    private final LocalIdMap mLocalIdUpdateMap;

    @NotNull
    private final RelationshipGraph mRelationshipGraph;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final <N extends DBModel> ModelIdentity<N> getSingleFieldIdentity(@NotNull ModelType<N> modelType, Long l) {
            Intrinsics.checkNotNullParameter(modelType, "modelType");
            Set<ModelField<M, Long>> identityFields = modelType.getIdentityFields();
            if (identityFields.size() == 1) {
                return new UnboundModelSingleFieldIdentity(l, (ModelField) identityFields.iterator().next());
            }
            throw new IllegalArgumentException(modelType + " does not have single field identity.");
        }

        public final <N extends DBModel> ModelField<N, Long> getSingleIdentityField(@NotNull ModelType<N> modelType) {
            Intrinsics.checkNotNullParameter(modelType, "modelType");
            Set<ModelField<M, Long>> identityFields = modelType.getIdentityFields();
            if (identityFields.size() == 1) {
                return (ModelField) identityFields.iterator().next();
            }
            return null;
        }

        @NotNull
        public final Set<ModelIdentity<? extends DBModel>> identitiesForModels(List<? extends DBModel> list) {
            if (list == null || list.isEmpty()) {
                return M.a;
            }
            if (list.size() == 1) {
                return Z.b(((DBModel) CollectionsKt.L(list)).getIdentity());
            }
            HashSet hashSet = new HashSet();
            Iterator<? extends DBModel> it2 = list.iterator();
            while (it2.hasNext()) {
                hashSet.add(it2.next().getIdentity());
            }
            return hashSet;
        }

        @NotNull
        public final <N extends DBModel> Map<ModelIdentity<N>, N> identityMap(List<? extends N> list) {
            if (list == null || list.isEmpty()) {
                return new LinkedHashMap();
            }
            int iA = U.a(C.q(list, 10));
            if (iA < 16) {
                iA = 16;
            }
            LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
            for (Object obj : list) {
                linkedHashMap.put(((DBModel) obj).getIdentity(), obj);
            }
            return V.m(linkedHashMap);
        }

        @NotNull
        public final <N extends DBModel> C0219q localIdMap(List<? extends N> list) {
            C0219q c0219q = new C0219q((Object) null);
            if (list != null) {
                for (N n : list) {
                    if (n.getLocalId() < 0) {
                        c0219q.g(n.getLocalId(), n);
                    }
                }
            }
            return c0219q;
        }

        @NotNull
        public final C0219q singleFieldIdentityMap(List<? extends DBModel> list) {
            if (list == null || list.isEmpty()) {
                return new C0219q(0);
            }
            C0219q c0219q = new C0219q((Object) null);
            for (DBModel dBModel : list) {
                Long singleFieldIdentityValue = dBModel.getIdentity().getSingleFieldIdentityValue();
                Intrinsics.d(singleFieldIdentityValue);
                c0219q.g(singleFieldIdentityValue.longValue(), dBModel);
            }
            return c0219q;
        }

        public final <N extends DBModel> boolean usesLocalIdAsPrimaryKey(@NotNull ModelType<N> modelType) {
            Intrinsics.checkNotNullParameter(modelType, "modelType");
            return getSingleIdentityField(modelType) == null;
        }

        private Companion() {
        }
    }

    public ModelIdentityProvider(@NotNull LocalIdMap mLocalIdUpdateMap, @NotNull RelationshipGraph mRelationshipGraph, @NotNull DatabaseHelper database, @NotNull ExecutionRouter executionRouter) {
        Intrinsics.checkNotNullParameter(mLocalIdUpdateMap, "mLocalIdUpdateMap");
        Intrinsics.checkNotNullParameter(mRelationshipGraph, "mRelationshipGraph");
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(executionRouter, "executionRouter");
        this.mLocalIdUpdateMap = mLocalIdUpdateMap;
        this.mRelationshipGraph = mRelationshipGraph;
        this.database = database;
        this.executionRouter = executionRouter;
        this.localIdAutoDecrementMap = new LinkedHashMap();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final DBModel generateLocalIdIfNeededAsync$lambda$1(DBModel dBModel, ModelIdentityProvider modelIdentityProvider) {
        modelIdentityProvider.generateLocalIdIfNeeded(dBModel);
        return dBModel;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final List generateLocalIdsIfNeededAsync$lambda$4(List list, ModelIdentityProvider modelIdentityProvider) {
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            DBModel dBModel = (DBModel) it2.next();
            modelIdentityProvider.generateLocalIdIfNeeded(dBModel);
            arrayList.add(dBModel);
        }
        return arrayList;
    }

    private final <M extends DBModel> long getNextLocalIdFor(ModelType<M> modelType) {
        long jDecrementAndGet;
        synchronized (this.localIdAutoDecrementMap) {
            try {
                Map<ModelType<? extends DBModel>, AtomicLong> map = this.localIdAutoDecrementMap;
                AtomicLong atomicLongQueryDbForInitialLocalId = map.get(modelType);
                if (atomicLongQueryDbForInitialLocalId == null) {
                    atomicLongQueryDbForInitialLocalId = queryDbForInitialLocalId(modelType);
                    map.put(modelType, atomicLongQueryDbForInitialLocalId);
                }
                jDecrementAndGet = atomicLongQueryDbForInitialLocalId.decrementAndGet();
            } catch (Throwable th) {
                throw th;
            }
        }
        return jDecrementAndGet;
    }

    @NotNull
    public static final <N extends DBModel> ModelIdentity<N> getSingleFieldIdentity(@NotNull ModelType<N> modelType, Long l) {
        return Companion.getSingleFieldIdentity(modelType, l);
    }

    public static final <N extends DBModel> ModelField<N, Long> getSingleIdentityField(@NotNull ModelType<N> modelType) {
        return Companion.getSingleIdentityField(modelType);
    }

    @NotNull
    public static final Set<ModelIdentity<? extends DBModel>> identitiesForModels(List<? extends DBModel> list) {
        return Companion.identitiesForModels(list);
    }

    @NotNull
    public static final <N extends DBModel> Map<ModelIdentity<N>, N> identityMap(List<? extends N> list) {
        return Companion.identityMap(list);
    }

    @NotNull
    public static final <N extends DBModel> C0219q localIdMap(List<? extends N> list) {
        return Companion.localIdMap(list);
    }

    private final <M extends DBModel> AtomicLong queryDbForInitialLocalId(ModelType<M> modelType) {
        Object objB = new b(new A(6, this, modelType), 6).g(new h() { // from class: com.quizlet.db.data.models.identity.ModelIdentityProvider.queryDbForInitialLocalId.2
            @Override // io.reactivex.rxjava3.functions.h
            public /* bridge */ /* synthetic */ Object apply(Object obj) {
                return apply(((Number) obj).longValue());
            }

            public final AtomicLong apply(long j) {
                return new AtomicLong(j);
            }
        }).l(this.executionRouter.c()).b();
        Intrinsics.checkNotNullExpressionValue(objB, "blockingGet(...)");
        return (AtomicLong) objB;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Long queryDbForInitialLocalId$lambda$0(ModelIdentityProvider modelIdentityProvider, ModelType modelType) {
        DBModel dBModel = (DBModel) modelIdentityProvider.database.j(modelType).queryBuilder().orderBy("localGeneratedId", true).queryForFirst();
        return Long.valueOf((dBModel == null || dBModel.getLocalId() >= 0) ? -1L : dBModel.getLocalId());
    }

    @NotNull
    public static final C0219q singleFieldIdentityMap(List<? extends DBModel> list) {
        return Companion.singleFieldIdentityMap(list);
    }

    private final <N extends DBModel> void updateDatabasePrimaryKeyIfNeeded(N n, ModelIdentity<N> modelIdentity) throws SQLException {
        int iUpdate;
        Companion companion = Companion;
        if (companion.usesLocalIdAsPrimaryKey(n.getModelType())) {
            return;
        }
        if (companion.getSingleIdentityField(n.getModelType()) == null) {
            throw new IllegalArgumentException("Multi-field identity models must use localId as their primary key");
        }
        if (n.getLocalId() == 0) {
            throw new IllegalArgumentException("Can't update identity for models that have no localId");
        }
        Dao daoJ = this.database.j(n.getModelType());
        UpdateBuilder<T, ID> updateBuilder = daoJ.updateBuilder();
        updateBuilder.where().eq("localGeneratedId", Long.valueOf(n.getLocalId()));
        modelIdentity.apply(updateBuilder);
        try {
            iUpdate = updateBuilder.update();
        } catch (SQLException e) {
            if (!(e.getCause() instanceof SQLiteConstraintException)) {
                throw e;
            }
            a aVar = c.a;
            aVar.o("Violated identity constraint on %s when updating %s with %s. Deleting existing copy.", n.getClass(), n, modelIdentity);
            DeleteBuilder deleteBuilder = daoJ.deleteBuilder();
            modelIdentity.whereEq(deleteBuilder.where());
            int iDelete = deleteBuilder.delete();
            if (iDelete != 1) {
                aVar.e(new RuntimeException(android.support.v4.media.session.a.f(iDelete, "Deleted unexpected number of records when resolving identity conflict: ")));
            }
            iUpdate = updateBuilder.update();
        }
        if (iUpdate > 1) {
            c.a.e(new RuntimeException(iUpdate + " rows exist for " + n.getClass() + " with localId: " + n.getLocalId()));
        }
        updateRelatedModelsForIdentityChange(n, modelIdentity);
    }

    private final <N extends DBModel> void updateRelatedModelsForIdentityChange(N n, ModelIdentity<N> modelIdentity) throws SQLException {
        if (modelIdentity.getSingleFieldIdentityValue() != null) {
            for (Relationship<? extends DBModel, N> relationship : this.mRelationshipGraph.getToManyRelationships(n.getModelType())) {
                Dao daoJ = this.database.j(relationship.getFromModelType());
                Intrinsics.checkNotNullExpressionValue(daoJ, "getNoDeleteFilterDao(...)");
                UpdateBuilder updateBuilder = daoJ.updateBuilder();
                updateBuilder.updateColumnValue(relationship.getFromFieldName(), modelIdentity.getSingleFieldIdentityValue());
                updateBuilder.where().eq(relationship.getFromFieldName(), Long.valueOf(n.getLocalId()));
                updateBuilder.update();
            }
        }
    }

    public static final <N extends DBModel> boolean usesLocalIdAsPrimaryKey(@NotNull ModelType<N> modelType) {
        return Companion.usesLocalIdAsPrimaryKey(modelType);
    }

    public final <M extends DBModel> void generateLocalIdIfNeeded(@NotNull M model) {
        Long singleFieldIdentityValue;
        Intrinsics.checkNotNullParameter(model, "model");
        if (model.getLocalId() == 0) {
            long nextLocalIdFor = getNextLocalIdFor(model.getModelType());
            model.setLocalId(nextLocalIdFor);
            if (Companion.getSingleIdentityField(model.getModelType()) == null || (singleFieldIdentityValue = model.getIdentity().getSingleFieldIdentityValue()) == null || singleFieldIdentityValue.longValue() > 0) {
                return;
            }
            new UnboundModelSingleFieldIdentity(model.getModelType(), nextLocalIdFor).apply(model);
        }
    }

    @NotNull
    public final <M extends DBModel> p<M> generateLocalIdIfNeededAsync(@NotNull M model) {
        Intrinsics.checkNotNullParameter(model, "model");
        k kVarH = new b(new A(7, model, this), 6).l(this.executionRouter.i()).h(e.c);
        Intrinsics.checkNotNullExpressionValue(kVarH, "observeOn(...)");
        return kVarH;
    }

    @NotNull
    public final <M extends DBModel> p<List<M>> generateLocalIdsIfNeededAsync(@NotNull List<? extends M> models) {
        Intrinsics.checkNotNullParameter(models, "models");
        k kVarH = new b(new A(5, models, this), 6).l(this.executionRouter.i()).h(e.c);
        Intrinsics.checkNotNullExpressionValue(kVarH, "observeOn(...)");
        return kVarH;
    }

    public final <N extends DBModel> void updateCachedModelWithServerIdInDatabase(List<? extends N> list, List<? extends N> list2) throws SQLException {
        if (list == null || list2 == null) {
            return;
        }
        int size = list.size();
        for (int i = 0; i < size; i++) {
            int size2 = list2.size();
            for (int i2 = 0; i2 < size2; i2++) {
                if (list.get(i).getLocalId() == list2.get(i2).getLocalId()) {
                    updateCachedModelWithServerIdInDatabase(list.get(i), list2.get(i2));
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x00b4 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0008 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final <N extends com.quizlet.db.data.models.base.DBModel> void updateLocalId(java.util.List<? extends N> r10, java.util.List<? extends N> r11, java.util.List<? extends N> r12) {
        /*
            r9 = this;
            if (r12 != 0) goto L4
            goto Lc5
        L4:
            java.util.Iterator r12 = r12.iterator()
        L8:
            boolean r0 = r12.hasNext()
            if (r0 == 0) goto Lc5
            java.lang.Object r0 = r12.next()
            com.quizlet.db.data.models.base.DBModel r0 = (com.quizlet.db.data.models.base.DBModel) r0
            com.quizlet.db.data.models.identity.ModelIdentity r1 = r0.getIdentity()
            com.quizlet.db.data.models.persisted.base.ModelType r2 = r0.getModelType()
            boolean r2 = r2.hasMultipleFieldIdentity()
            if (r2 != 0) goto L29
            boolean r3 = r1.hasServerIdentity()
            if (r3 == 0) goto L29
            goto L8
        L29:
            r3 = 1
            r4 = 0
            if (r2 == 0) goto L6e
            if (r10 == 0) goto L4e
            java.util.Iterator r2 = r10.iterator()
        L33:
            boolean r5 = r2.hasNext()
            if (r5 == 0) goto L4e
            java.lang.Object r5 = r2.next()
            com.quizlet.db.data.models.base.DBModel r5 = (com.quizlet.db.data.models.base.DBModel) r5
            com.quizlet.db.data.models.identity.ModelIdentity r6 = r5.getIdentity()
            boolean r6 = kotlin.jvm.internal.Intrinsics.b(r6, r1)
            if (r6 == 0) goto L33
            r9.updateLocalId(r5, r0)
            r4 = r3
            goto L33
        L4e:
            if (r4 != 0) goto Lb2
            if (r11 == 0) goto Lb2
            java.util.Iterator r2 = r11.iterator()
        L56:
            boolean r5 = r2.hasNext()
            if (r5 == 0) goto Lb2
            java.lang.Object r5 = r2.next()
            com.quizlet.db.data.models.base.DBModel r5 = (com.quizlet.db.data.models.base.DBModel) r5
            com.quizlet.db.data.models.identity.ModelIdentity r5 = r5.getIdentity()
            boolean r5 = kotlin.jvm.internal.Intrinsics.b(r5, r1)
            if (r5 == 0) goto L56
        L6c:
            r4 = r3
            goto Lb2
        L6e:
            if (r10 == 0) goto L91
            java.util.Iterator r1 = r10.iterator()
        L74:
            boolean r2 = r1.hasNext()
            if (r2 == 0) goto L91
            java.lang.Object r2 = r1.next()
            com.quizlet.db.data.models.base.DBModel r2 = (com.quizlet.db.data.models.base.DBModel) r2
            long r5 = r2.getLocalId()
            long r7 = r0.getLocalId()
            int r5 = (r5 > r7 ? 1 : (r5 == r7 ? 0 : -1))
            if (r5 != 0) goto L74
            r9.updateLocalId(r2, r0)
            r4 = r3
            goto L74
        L91:
            if (r4 != 0) goto Lb2
            if (r11 == 0) goto Lb2
            java.util.Iterator r1 = r11.iterator()
        L99:
            boolean r2 = r1.hasNext()
            if (r2 == 0) goto Lb2
            java.lang.Object r2 = r1.next()
            com.quizlet.db.data.models.base.DBModel r2 = (com.quizlet.db.data.models.base.DBModel) r2
            long r5 = r2.getLocalId()
            long r7 = r0.getLocalId()
            int r2 = (r5 > r7 ? 1 : (r5 == r7 ? 0 : -1))
            if (r2 != 0) goto L99
            goto L6c
        Lb2:
            if (r4 != 0) goto L8
            timber.log.a r1 = timber.log.c.a
            java.lang.IllegalStateException r2 = new java.lang.IllegalStateException
            java.lang.String r4 = "Cached model not found in either valid or invalid server results. Deleting"
            r2.<init>(r4)
            r1.e(r2)
            r0.setDeleted(r3)
            goto L8
        Lc5:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.db.data.models.identity.ModelIdentityProvider.updateLocalId(java.util.List, java.util.List, java.util.List):void");
    }

    public final <M extends DBModel> void validateId(@NotNull M model, M m) {
        Intrinsics.checkNotNullParameter(model, "model");
        if (m == null || m.getLocalId() >= 0) {
            generateLocalIdIfNeeded(model);
        } else {
            model.setLocalId(m.getLocalId());
        }
    }

    private final <N extends DBModel> void updateCachedModelWithServerIdInDatabase(N n, N n2) throws SQLException {
        if (n2 == null || !n.getIdentity().hasServerIdentity()) {
            return;
        }
        updateDatabasePrimaryKeyIfNeeded(n2, n.getIdentity());
    }

    private final <N extends DBModel> void updateLocalId(N n, N n2) {
        n.setLocalId(n2.getLocalId());
        LocalIdMap localIdMap = this.mLocalIdUpdateMap;
        localIdMap.getClass();
        Long singleFieldIdentityValue = n.getIdentity().getSingleFieldIdentityValue();
        long localId = n.getLocalId();
        if (singleFieldIdentityValue == null || singleFieldIdentityValue.longValue() <= 0) {
            return;
        }
        ModelType modelType = n.getModelType();
        HashMap map = localIdMap.b;
        if (!map.containsKey(modelType)) {
            map.put(modelType, new C0219q((Object) null));
        }
        ((C0219q) map.get(modelType)).g(localId, singleFieldIdentityValue);
        ModelIdentity identity = n.getIdentity();
        if (identity.getSingleFieldIdentityValue() != null) {
            localIdMap.a.b(new ServerIdAssignmentEvent(n.getModelType(), Long.valueOf(n.getLocalId()), identity.getSingleFieldIdentityValue()));
        }
    }
}
