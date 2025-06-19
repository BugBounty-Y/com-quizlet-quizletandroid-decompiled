package com.quizlet.db.data.models.persisted.types;

import com.quizlet.api.model.ModelWrapper;
import com.quizlet.assembly.compose.listitems.r;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields;
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
public final class DiagramShapeModel extends ModelType<DBDiagramShape> {

    @NotNull
    private final k mIdentityFields$delegate = l.b(new r(23));

    private final Set<ModelField<DBDiagramShape, Long>> getMIdentityFields() {
        return (Set) this.mIdentityFields$delegate.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Set mIdentityFields_delegate$lambda$0() {
        return Z.b(DBDiagramShapeFields.ID);
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public String getEndpointRoot() {
        return "diagram-shapes";
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Set<ModelField<DBDiagramShape, Long>> getIdentityFields() {
        return getMIdentityFields();
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public ModelField<DBDiagramShape, Long> getLocalIdField() {
        ModelField<DBDiagramShape, Long> LOCAL_ID = DBDiagramShapeFields.LOCAL_ID;
        Intrinsics.checkNotNullExpressionValue(LOCAL_ID, "LOCAL_ID");
        return LOCAL_ID;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    @NotNull
    public Class<DBDiagramShape> getModelClass() {
        return DBDiagramShape.class;
    }

    @Override // com.quizlet.db.data.models.persisted.base.ModelType
    public List<DBDiagramShape> getModels(@NotNull ModelWrapper modelWrapper) {
        Intrinsics.checkNotNullParameter(modelWrapper, "modelWrapper");
        return modelWrapper.getDiagramShapes();
    }
}
