package com.quizlet.api.error;

import com.quizlet.api.model.ApiError;

/* loaded from: classes2.dex */
public class ApiErrorException extends RuntimeException {
    private ApiError mApiError;

    public ApiErrorException(ApiError apiError) {
        super(apiError.getServerMessage());
        this.mApiError = apiError;
    }

    public ApiError getError() {
        return this.mApiError;
    }
}
