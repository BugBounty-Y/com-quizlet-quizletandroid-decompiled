package com.quizlet.api.error;

import com.quizlet.api.model.ValidationError;

/* loaded from: classes2.dex */
public class ValidationErrorException extends RuntimeException {
    private ValidationError mValidationError;

    public ValidationErrorException(ValidationError validationError) {
        super(validationError.getServerMessage());
        this.mValidationError = validationError;
    }

    public ValidationError getError() {
        return this.mValidationError;
    }
}
