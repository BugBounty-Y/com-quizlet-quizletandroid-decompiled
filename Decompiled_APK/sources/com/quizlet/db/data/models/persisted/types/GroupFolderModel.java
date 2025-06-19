package com.quizlet.db.data.models.persisted.types;

import com.quizlet.api.model.ModelWrapper;
import com.quizlet.assembly.compose.listitems.r;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBGroupFolder;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBGroupFolderFields;
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
public final class GroupFolderModel extends ModelType<DBGroupFolder> {

    @NotNull
    private final k mIdentityFields$delegate = l.b(new r(26));

    private final Set<ModelField<DBGroupFolder, Long>> getMIdentityFields() {
        return (Set) this.mIdentityFields$delegate.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Set mIdentityFields_delegate$lambda$0() {
        DBGroupFolderFields dBGroupFolderFields = DBGroupFolderFields.INSTANCE;
        Relationship[] elements = {dBGroupFolderFields.getGROUP(), dBGroupFolderFields.getFOLDER()};
        Intrinsics.checkNotNullParameter(elements, "elements");
        return C4933y.T(elements);
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public String getEndpointRoot() {
        return "class-folders";
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Set<ModelField<DBGroupFolder, Long>> getIdentityFields() {
        return getMIdentityFields();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public ModelField<DBGroupFolder, Long> getLocalIdField() {
        return DBGroupFolderFields.INSTANCE.getLOCAL_ID();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Class<DBGroupFolder> getModelClass() {
        return DBGroupFolder.class;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public List<DBGroupFolder> getModels(ModelWrapper modelWrapper) {
        if (modelWrapper != null) {
            return modelWrapper.getGroupFolders();
        }
        return null;
    }
}
