package com.quizlet.db.data.models.persisted.types;

import com.quizlet.api.model.ModelWrapper;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBSchool;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBSchoolFields;
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
public final class SchoolModel extends ModelType<DBSchool> {

    @NotNull
    private final k mIdentityFields$delegate = l.b(new a(5));

    private final Set<ModelField<DBSchool, Long>> getMIdentityFields() {
        return (Set) this.mIdentityFields$delegate.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Set mIdentityFields_delegate$lambda$0() {
        return Z.b(DBSchoolFields.ID);
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public String getEndpointRoot() {
        return "schools";
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Set<ModelField<DBSchool, Long>> getIdentityFields() {
        return getMIdentityFields();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public ModelField<DBSchool, Long> getLocalIdField() {
        ModelField<DBSchool, Long> LOCAL_ID = DBSchoolFields.LOCAL_ID;
        Intrinsics.checkNotNullExpressionValue(LOCAL_ID, "LOCAL_ID");
        return LOCAL_ID;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Class<DBSchool> getModelClass() {
        return DBSchool.class;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public List<DBSchool> getModels(@NotNull ModelWrapper modelWrapper) {
        Intrinsics.checkNotNullParameter(modelWrapper, "modelWrapper");
        return modelWrapper.getSchools();
    }
}
