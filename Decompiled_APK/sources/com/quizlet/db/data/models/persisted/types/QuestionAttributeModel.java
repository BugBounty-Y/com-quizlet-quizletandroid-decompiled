package com.quizlet.db.data.models.persisted.types;

import com.quizlet.api.model.ModelWrapper;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBQuestionAttribute;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields;
import java.util.List;
import java.util.Set;
import kotlin.Metadata;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;
import kotlin.k;
import kotlin.l;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class QuestionAttributeModel extends ModelType<DBQuestionAttribute> {

    @NotNull
    private final k mIdentityFields$delegate = l.b(new a(4));

    private final Set<ModelField<DBQuestionAttribute, Long>> getMIdentityFields() {
        return (Set) this.mIdentityFields$delegate.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Set mIdentityFields_delegate$lambda$0() {
        return Z.b(DBQuestionAttributeFields.ID);
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public String getEndpointRoot() {
        return "question-attributes";
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Set<ModelField<DBQuestionAttribute, Long>> getIdentityFields() {
        return getMIdentityFields();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public ModelField<DBQuestionAttribute, Long> getLocalIdField() {
        ModelField<DBQuestionAttribute, Long> LOCAL_ID = DBQuestionAttributeFields.LOCAL_ID;
        Intrinsics.checkNotNullExpressionValue(LOCAL_ID, "LOCAL_ID");
        return LOCAL_ID;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Class<DBQuestionAttribute> getModelClass() {
        return DBQuestionAttribute.class;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public List<DBQuestionAttribute> getModels(@NotNull ModelWrapper modelWrapper) {
        Intrinsics.checkNotNullParameter(modelWrapper, "modelWrapper");
        return modelWrapper.getQuestionAttributes();
    }
}
