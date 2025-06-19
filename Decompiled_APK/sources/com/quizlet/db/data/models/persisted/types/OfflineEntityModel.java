package com.quizlet.db.data.models.persisted.types;

import com.quizlet.api.model.ModelWrapper;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBOfflineEntity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import java.util.List;
import java.util.Set;
import kotlin.Metadata;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlin.k;
import kotlin.l;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class OfflineEntityModel extends ModelType<DBOfflineEntity> {

    @NotNull
    private final k mIdentityFields$delegate = l.b(new a(2));

    private final Set<ModelField<DBOfflineEntity, Long>> getMIdentityFields() {
        return (Set) this.mIdentityFields$delegate.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Set mIdentityFields_delegate$lambda$0() {
        ModelField[] elements = {DBOfflineEntityFields.MODEL_ID, DBOfflineEntityFields.MODEL_TYPE};
        Intrinsics.checkNotNullParameter(elements, "elements");
        return C4933y.T(elements);
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public String getEndpointRoot() {
        return "";
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Set<ModelField<DBOfflineEntity, Long>> getIdentityFields() {
        return getMIdentityFields();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public ModelField<DBOfflineEntity, Long> getLocalIdField() {
        ModelField<DBOfflineEntity, Long> LOCAL_ID = DBOfflineEntityFields.LOCAL_ID;
        Intrinsics.checkNotNullExpressionValue(LOCAL_ID, "LOCAL_ID");
        return LOCAL_ID;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Class<DBOfflineEntity> getModelClass() {
        return DBOfflineEntity.class;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public List<DBOfflineEntity> getModels(@NotNull ModelWrapper modelWrapper) {
        Intrinsics.checkNotNullParameter(modelWrapper, "modelWrapper");
        return null;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public boolean supportsServerSync() {
        return false;
    }
}
