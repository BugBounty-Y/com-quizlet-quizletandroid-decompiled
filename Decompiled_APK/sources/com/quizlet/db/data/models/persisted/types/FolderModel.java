package com.quizlet.db.data.models.persisted.types;

import com.quizlet.api.model.ModelWrapper;
import com.quizlet.assembly.compose.listitems.r;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBFolderFields;
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
public final class FolderModel extends ModelType<DBFolder> {

    @NotNull
    private final k mIdentityFields$delegate = l.b(new r(25));

    private final Set<ModelField<DBFolder, Long>> getMIdentityFields() {
        return (Set) this.mIdentityFields$delegate.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Set mIdentityFields_delegate$lambda$0() {
        return Z.b(DBFolderFields.ID);
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public String getEndpointRoot() {
        return "folders";
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Set<ModelField<DBFolder, Long>> getIdentityFields() {
        return getMIdentityFields();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public ModelField<DBFolder, Long> getLocalIdField() {
        ModelField<DBFolder, Long> LOCAL_ID = DBFolderFields.LOCAL_ID;
        Intrinsics.checkNotNullExpressionValue(LOCAL_ID, "LOCAL_ID");
        return LOCAL_ID;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Class<DBFolder> getModelClass() {
        return DBFolder.class;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public List<DBFolder> getModels(@NotNull ModelWrapper modelWrapper) {
        Intrinsics.checkNotNullParameter(modelWrapper, "modelWrapper");
        return modelWrapper.getFolders();
    }
}
