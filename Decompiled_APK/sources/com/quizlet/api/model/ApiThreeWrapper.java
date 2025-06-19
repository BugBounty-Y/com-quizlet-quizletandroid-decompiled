package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
/* loaded from: classes2.dex */
public class ApiThreeWrapper<T> {
    private ApiError error;
    private List<ApiResponse<T>> responses;

    public ApiError getError() {
        return this.error;
    }

    public T getFirstData() {
        List<ApiResponse<T>> list = this.responses;
        if (list == null || list.size() <= 0) {
            return null;
        }
        return this.responses.get(0).getDataWrapper();
    }

    public List<ApiResponse<T>> getResponses() {
        return this.responses;
    }

    public void setError(ApiError apiError) {
        this.error = apiError;
    }

    public void setResponses(List<ApiResponse<T>> list) {
        this.responses = list;
    }
}
