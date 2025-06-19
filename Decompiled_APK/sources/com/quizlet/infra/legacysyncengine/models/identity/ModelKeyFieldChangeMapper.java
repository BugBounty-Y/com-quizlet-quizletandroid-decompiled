package com.quizlet.infra.legacysyncengine.models.identity;

import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.RelationshipGraph;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.net.localid.LocalIdMap;
import com.quizlet.db.data.orm.Relationship;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes3.dex */
public class ModelKeyFieldChangeMapper {
    protected final LocalIdMap mLocalIdMap;
    protected final RelationshipGraph mRelationshipGraph;

    public ModelKeyFieldChangeMapper(LocalIdMap localIdMap, RelationshipGraph relationshipGraph) {
        this.mLocalIdMap = localIdMap;
        this.mRelationshipGraph = relationshipGraph;
    }

    public <N extends DBModel> void updateIdsAndForeignKeys(List<N> list) {
        updateStaleLocalIdentityFields(list);
        updateStaleLocalForeignKeys(list);
    }

    public <N extends DBModel> void updateStaleLocalForeignKeys(List<N> list) {
        Iterator<N> it2 = list.iterator();
        while (it2.hasNext()) {
            updateStaleLocalForeignKeys((ModelKeyFieldChangeMapper) it2.next());
        }
    }

    public <N extends DBModel> void updateStaleLocalIdentityFields(List<N> list) {
        ModelType modelType;
        Long lA;
        for (N n : list) {
            Long singleFieldIdentityValue = n.getIdentity().getSingleFieldIdentityValue();
            if (singleFieldIdentityValue != null && singleFieldIdentityValue.longValue() < 0 && (lA = this.mLocalIdMap.a((modelType = n.getModelType()), singleFieldIdentityValue)) != null) {
                ModelIdentityProvider.getSingleFieldIdentity(modelType, lA).apply(n);
            }
        }
    }

    public <N extends DBModel> void updateStaleLocalForeignKeys(N n) {
        Long singleFieldIdentityValue;
        for (Relationship<N, ? extends DBModel> relationship : this.mRelationshipGraph.getToOneRelationships(n.getModelType())) {
            ModelIdentity<T> toModelIdentity = relationship.getToModelIdentity(n);
            if (toModelIdentity != 0 && (singleFieldIdentityValue = toModelIdentity.getSingleFieldIdentityValue()) != null && singleFieldIdentityValue.longValue() < 0) {
                ModelType modelType = relationship.getToModelIdentity(n).getModelType();
                Long lA = this.mLocalIdMap.a(modelType, singleFieldIdentityValue);
                if (modelType != null && lA != null) {
                    relationship.setToModelIdentity(n, ModelIdentityProvider.getSingleFieldIdentity(modelType, lA));
                }
            }
        }
    }
}
