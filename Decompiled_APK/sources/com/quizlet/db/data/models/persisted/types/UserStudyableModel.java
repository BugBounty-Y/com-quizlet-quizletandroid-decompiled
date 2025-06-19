package com.quizlet.db.data.models.persisted.types;

import com.quizlet.api.model.ModelWrapper;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBUserStudyable;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields;
import com.quizlet.db.data.orm.Relationship;
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
public final class UserStudyableModel extends ModelType<DBUserStudyable> {

    @NotNull
    private final k mIdentityFields$delegate = l.b(new a(12));

    private final Set<ModelField<DBUserStudyable, Long>> getMIdentityFields() {
        return (Set) this.mIdentityFields$delegate.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Set mIdentityFields_delegate$lambda$0() {
        Relationship[] elements = {DBUserStudyableFields.PERSON, DBUserStudyableFields.SET};
        Intrinsics.checkNotNullParameter(elements, "elements");
        return C4933y.T(elements);
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public String getEndpointRoot() {
        return "user-studyables";
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Set<ModelField<DBUserStudyable, Long>> getIdentityFields() {
        return getMIdentityFields();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public ModelField<DBUserStudyable, Long> getLocalIdField() {
        ModelField<DBUserStudyable, Long> LOCAL_ID = DBUserStudyableFields.LOCAL_ID;
        Intrinsics.checkNotNullExpressionValue(LOCAL_ID, "LOCAL_ID");
        return LOCAL_ID;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Class<DBUserStudyable> getModelClass() {
        return DBUserStudyable.class;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public List<DBUserStudyable> getModels(@NotNull ModelWrapper modelWrapper) {
        Intrinsics.checkNotNullParameter(modelWrapper, "modelWrapper");
        return modelWrapper.getUserStudyables();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public int getSyncPageSize() {
        return 1;
    }
}
