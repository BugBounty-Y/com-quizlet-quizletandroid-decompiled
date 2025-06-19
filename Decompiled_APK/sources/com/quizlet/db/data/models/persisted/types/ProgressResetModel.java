package com.quizlet.db.data.models.persisted.types;

import com.quizlet.api.model.ModelWrapper;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBProgressReset;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBProgressResetFields;
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
public final class ProgressResetModel extends ModelType<DBProgressReset> {

    @NotNull
    private final k mIdentityFields$delegate = l.b(new a(3));

    private final Set<ModelField<DBProgressReset, Long>> getMIdentityFields() {
        return (Set) this.mIdentityFields$delegate.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Set mIdentityFields_delegate$lambda$0() {
        DBProgressResetFields dBProgressResetFields = DBProgressResetFields.INSTANCE;
        ModelField[] elements = {dBProgressResetFields.getCONTAINER(), dBProgressResetFields.getCONTAINER_TYPE(), dBProgressResetFields.getUSER()};
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
    public Set<ModelField<DBProgressReset, Long>> getIdentityFields() {
        return getMIdentityFields();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public ModelField<DBProgressReset, Long> getLocalIdField() {
        return DBProgressResetFields.INSTANCE.getLOCAL_ID();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Class<DBProgressReset> getModelClass() {
        return DBProgressReset.class;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public List<DBProgressReset> getModels(ModelWrapper modelWrapper) {
        return null;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public boolean supportsServerSync() {
        return false;
    }
}
