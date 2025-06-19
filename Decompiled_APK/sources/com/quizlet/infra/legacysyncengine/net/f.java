package com.quizlet.infra.legacysyncengine.net;

import androidx.camera.camera2.internal.T;
import androidx.compose.ui.node.V;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.common.api.internal.k;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.RelationshipGraph;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.db.data.orm.Include;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import com.quizlet.infra.legacysyncengine.managers.i;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.operators.observable.E;
import io.reactivex.rxjava3.internal.operators.observable.W;
import io.reactivex.rxjava3.subjects.p;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/* loaded from: classes3.dex */
public final class f {
    public static final HashSet i = new HashSet(Arrays.asList(Models.ANSWER, Models.QUESTION_ATTRIBUTE, Models.FOLDER, Models.GROUP, Models.SCHOOL, Models.GROUP_MEMBERSHIP, Models.SELECTED_TERM, Models.SESSION, Models.STUDY_SET, Models.STUDY_SETTING, Models.TERM, Models.USER, Models.IMAGE, Models.USER_STUDYABLE));
    public final RelationshipGraph a;
    public final i b;
    public final V c;
    public final ExecutionRouter d;
    public final com.quizlet.db.token.a e;
    public final Set f;
    public final HashSet g = new HashSet();
    public final HashMap h = new HashMap();

    public f(RelationshipGraph relationshipGraph, i iVar, ExecutionRouter executionRouter, V v, com.quizlet.db.token.a aVar, Set set) {
        this.a = relationshipGraph;
        this.b = iVar;
        this.d = executionRouter;
        this.c = v;
        this.e = aVar;
        this.f = set;
    }

    public final io.reactivex.rxjava3.core.i a(DBModel dBModel) {
        return b(Collections.singletonList(dBModel));
    }

    public final io.reactivex.rxjava3.core.i b(List list) throws Exception {
        if (list.isEmpty()) {
            return E.a;
        }
        ModelType modelType = ((DBModel) list.get(0)).getModelType();
        p pVarZ = p.z();
        this.b.a(list, new T(this, modelType, pVarZ, 22));
        return pVarZ;
    }

    public final io.reactivex.rxjava3.core.i c(ModelType modelType) {
        com.quizlet.infra.legacysyncengine.tasks.read.b cVar;
        String strA = this.e.a();
        E e = E.a;
        if (strA == null || !modelType.supportsServerSync()) {
            return e;
        }
        HashSet hashSet = this.g;
        if (hashSet.contains(modelType)) {
            HashMap map = this.h;
            if (!map.containsKey(modelType)) {
                map.put(modelType, p.z());
            }
            return (io.reactivex.rxjava3.core.i) map.get(modelType);
        }
        hashSet.add(modelType);
        V v = this.c;
        int syncPageSize = modelType.getSyncPageSize();
        s sVar = (s) v.f;
        k kVar = new k(modelType, syncPageSize, v, sVar, (ExecutionRouter) v.c);
        boolean zEquals = Models.STUDY_SET.equals(modelType);
        ExecutionRouter executionRouter = (ExecutionRouter) sVar.e;
        RelationshipGraph relationshipGraph = (RelationshipGraph) sVar.i;
        DatabaseHelper databaseHelper = (DatabaseHelper) sVar.b;
        if (zEquals) {
            cVar = new com.quizlet.infra.legacysyncengine.tasks.read.sync.b(modelType, databaseHelper, relationshipGraph, executionRouter.c());
        } else if (Models.TERM.equals(modelType)) {
            cVar = new com.quizlet.infra.legacysyncengine.tasks.read.sync.a(modelType, databaseHelper, relationshipGraph, executionRouter.c());
        } else if (Models.SESSION.equals(modelType)) {
            o oVarC = executionRouter.c();
            HashSet hashSet2 = new HashSet();
            HashSet hashSet3 = new HashSet(modelType.getAutomaticIncludes());
            Include include = new Include(DBSessionFields.STUDYABLE);
            if (!((Relationship) include.a.get(0)).getFromModelType().equals(modelType)) {
                throw new IllegalArgumentException("Include " + include + " does not correspond to model class: " + modelType);
            }
            hashSet3.add(include);
            cVar = new com.quizlet.infra.legacysyncengine.tasks.read.sync.a(new IdMappedQuery(new com.quizlet.infra.legacysyncengine.orm.query.a(modelType, com.google.common.collect.o.n(hashSet2), hashSet3)), databaseHelper, relationshipGraph, oVarC);
        } else {
            cVar = new com.quizlet.infra.legacysyncengine.tasks.read.c(modelType, databaseHelper, relationshipGraph, executionRouter.c());
        }
        io.reactivex.rxjava3.core.i iVarE = cVar.e();
        com.quizlet.infra.legacysyncengine.net.sync.a aVar = new com.quizlet.infra.legacysyncengine.net.sync.a(kVar, 0);
        int i2 = io.reactivex.rxjava3.core.e.a;
        io.reactivex.rxjava3.internal.functions.d.a(i2, "bufferSize");
        W wS = new W(iVarE, aVar, i2, 0).l(new com.quizlet.infra.legacysyncengine.models.serializers.a(5)).m(new com.quizlet.infra.legacysyncengine.net.sync.a(kVar, 1), SubsamplingScaleImageView.TILE_SIZE_AUTO).x(16).m().m(new com.google.firebase.tracing.a(15, this, modelType), SubsamplingScaleImageView.TILE_SIZE_AUTO).s(this.d.i());
        p pVarZ = p.z();
        wS.c(new com.quizlet.infra.legacysyncengine.utils.a(pVarZ, 0));
        return pVarZ;
    }
}
