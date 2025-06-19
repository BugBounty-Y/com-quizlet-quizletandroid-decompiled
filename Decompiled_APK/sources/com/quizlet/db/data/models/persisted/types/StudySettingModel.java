package com.quizlet.db.data.models.persisted.types;

import com.quizlet.api.model.ModelWrapper;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBStudySetting;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBStudySettingFields;
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
public final class StudySettingModel extends ModelType<DBStudySetting> {

    @NotNull
    private final k mIdentityFields$delegate = l.b(new a(9));

    private final Set<ModelField<DBStudySetting, Long>> getMIdentityFields() {
        return (Set) this.mIdentityFields$delegate.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Set mIdentityFields_delegate$lambda$0() {
        ModelField[] elements = {DBStudySettingFields.PERSON, DBStudySettingFields.STUDYABLE_TYPE, DBStudySettingFields.STUDYABLE, DBStudySettingFields.SETTING_TYPE};
        Intrinsics.checkNotNullParameter(elements, "elements");
        return C4933y.T(elements);
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public String getEndpointRoot() {
        return "study-settings";
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Set<ModelField<DBStudySetting, Long>> getIdentityFields() {
        return getMIdentityFields();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public ModelField<DBStudySetting, Long> getLocalIdField() {
        ModelField<DBStudySetting, Long> LOCAL_ID = DBStudySettingFields.LOCAL_ID;
        Intrinsics.checkNotNullExpressionValue(LOCAL_ID, "LOCAL_ID");
        return LOCAL_ID;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Class<DBStudySetting> getModelClass() {
        return DBStudySetting.class;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public List<DBStudySetting> getModels(@NotNull ModelWrapper modelWrapper) {
        Intrinsics.checkNotNullParameter(modelWrapper, "modelWrapper");
        return modelWrapper.getStudySettings();
    }
}
