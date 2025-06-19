package com.quizlet.db.data.models.persisted.types;

import com.quizlet.api.model.ModelWrapper;
import com.quizlet.assembly.compose.listitems.r;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBEnteredSetPassword;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBEnteredSetPasswordFields;
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
public final class EnteredSetPasswordModel extends ModelType<DBEnteredSetPassword> {

    @NotNull
    private final k mIdentityFields$delegate = l.b(new r(24));

    private final Set<ModelField<DBEnteredSetPassword, Long>> getMIdentityFields() {
        return (Set) this.mIdentityFields$delegate.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Set mIdentityFields_delegate$lambda$0() {
        Relationship[] elements = {DBEnteredSetPasswordFields.PERSON, DBEnteredSetPasswordFields.SET};
        Intrinsics.checkNotNullParameter(elements, "elements");
        return C4933y.T(elements);
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public String getEndpointRoot() {
        return "entered-set-passwords";
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Set<ModelField<DBEnteredSetPassword, Long>> getIdentityFields() {
        return getMIdentityFields();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public ModelField<DBEnteredSetPassword, Long> getLocalIdField() {
        ModelField<DBEnteredSetPassword, Long> LOCAL_ID = DBEnteredSetPasswordFields.LOCAL_ID;
        Intrinsics.checkNotNullExpressionValue(LOCAL_ID, "LOCAL_ID");
        return LOCAL_ID;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Class<DBEnteredSetPassword> getModelClass() {
        return DBEnteredSetPassword.class;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public List<DBEnteredSetPassword> getModels(@NotNull ModelWrapper modelWrapper) {
        Intrinsics.checkNotNullParameter(modelWrapper, "modelWrapper");
        return modelWrapper.getEnteredSetPasswords();
    }
}
