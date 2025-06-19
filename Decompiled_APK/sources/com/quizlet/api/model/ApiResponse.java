package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
/* loaded from: classes2.dex */
public class ApiResponse<T> {
    private T dataWrapper;
    private ModelError error;
    private ModelWrapper modelWrapper;
    private PagingInfo pagingInfo;
    private List<ValidationError> validationErrors;

    public T getDataWrapper() {
        return this.dataWrapper;
    }

    @JsonProperty("error")
    public ModelError getError() {
        return this.error;
    }

    public ModelWrapper getModelWrapper() {
        return this.modelWrapper;
    }

    public PagingInfo getPagingInfo() {
        return this.pagingInfo;
    }

    @JsonProperty("validationErrors")
    public List<ValidationError> getValidationErrors() {
        return this.validationErrors;
    }

    public boolean hasError() {
        return this.error != null;
    }

    public boolean hasValidationError() {
        List<ValidationError> list = this.validationErrors;
        return (list == null || list.isEmpty()) ? false : true;
    }

    @JsonProperty("data")
    public void setDataWrapper(T t) {
        this.dataWrapper = t;
    }

    public void setError(ModelError modelError) {
        this.error = modelError;
    }

    @JsonProperty("models")
    public void setModelWrapper(ModelWrapper modelWrapper) {
        this.modelWrapper = modelWrapper;
    }

    @JsonProperty("paging")
    public void setPagingInfo(PagingInfo pagingInfo) {
        this.pagingInfo = pagingInfo;
    }

    public void setValidationErrors(List<ValidationError> list) {
        this.validationErrors = list;
    }
}
