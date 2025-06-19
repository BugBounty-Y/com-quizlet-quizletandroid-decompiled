package com.quizlet.api.error;

import com.quizlet.api.model.ModelError;

/* loaded from: classes2.dex */
public class ModelErrorException extends RuntimeException {
    private ModelError mModelError;

    public ModelErrorException(ModelError modelError) {
        super(modelError.getServerMessage());
        this.mModelError = modelError;
    }

    public ModelError getError() {
        return this.mModelError;
    }
}
