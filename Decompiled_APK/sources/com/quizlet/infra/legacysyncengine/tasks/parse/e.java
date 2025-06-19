package com.quizlet.infra.legacysyncengine.tasks.parse;

import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ModelError;
import com.quizlet.api.model.ModelWrapper;
import com.quizlet.db.data.models.persisted.base.ModelType;
import java.util.List;

/* loaded from: classes3.dex */
public final class e {
    public final int a;
    public final ModelType b;
    public final List c;
    public final ModelError d;
    public final List e;

    public e(ModelType modelType, ApiResponse apiResponse, int i) {
        this.b = modelType;
        this.a = i;
        if (modelType == null || apiResponse.getModelWrapper() == null) {
            this.c = null;
        } else {
            this.c = modelType.getModels(apiResponse.getModelWrapper());
        }
        this.d = apiResponse.getError();
        this.e = apiResponse.getValidationErrors();
    }

    public e(ModelType modelType, ModelWrapper modelWrapper, int i) {
        this.b = modelType;
        this.a = i;
        this.c = modelType.getModels(modelWrapper);
        this.d = null;
        this.e = null;
    }
}
