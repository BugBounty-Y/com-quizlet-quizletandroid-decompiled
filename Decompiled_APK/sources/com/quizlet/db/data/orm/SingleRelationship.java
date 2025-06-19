package com.quizlet.db.data.orm;

import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.base.ModelType;
import java.util.Collections;

/* loaded from: classes2.dex */
public abstract class SingleRelationship<F extends DBModel, T extends DBModel> extends Relationship<F, T> {
    public SingleRelationship(ModelType modelType, String str, ModelType modelType2) {
        super(modelType, str, Collections.singletonList(modelType2));
    }

    @Override // com.quizlet.db.data.orm.Relationship
    public final ModelType<? extends T> getToModelType(F f) {
        return getToModelTypes().get(0);
    }

    @Override // com.quizlet.db.data.orm.Relationship
    public final ModelType<? extends T> getToModelType(Long l) {
        return getToModelTypes().get(0);
    }
}
