package com.quizlet.db.data.models.persisted.types;

import com.quizlet.api.model.ModelWrapper;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.db.data.orm.Include;
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
public final class TermModel extends ModelType<DBTerm> {

    @NotNull
    private final k mIdentityFields$delegate = l.b(new a(10));

    private final Set<ModelField<DBTerm, Long>> getMIdentityFields() {
        return (Set) this.mIdentityFields$delegate.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Set mIdentityFields_delegate$lambda$0() {
        return Z.b(DBTermFields.ID);
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Set<Include> getAutomaticIncludes() {
        return Z.b(new Include(DBTermFields.DEFINITION_IMAGE));
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public String getEndpointRoot() {
        return "terms";
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Set<ModelField<DBTerm, Long>> getIdentityFields() {
        return getMIdentityFields();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public ModelField<DBTerm, Long> getLocalIdField() {
        ModelField<DBTerm, Long> LOCAL_ID = DBTermFields.LOCAL_ID;
        Intrinsics.checkNotNullExpressionValue(LOCAL_ID, "LOCAL_ID");
        return LOCAL_ID;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Class<DBTerm> getModelClass() {
        return DBTerm.class;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public List<DBTerm> getModels(@NotNull ModelWrapper modelWrapper) {
        Intrinsics.checkNotNullParameter(modelWrapper, "modelWrapper");
        return modelWrapper.getTerms();
    }
}
