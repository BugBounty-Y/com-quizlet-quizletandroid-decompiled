package com.quizlet.api.model;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
/* loaded from: classes2.dex */
public class PagingInfo {
    private boolean isFeedFinished;
    private int page;
    private String pagingToken;
    private int total;

    public boolean getIsFeedFinished() {
        return this.isFeedFinished;
    }

    public int getPage() {
        return this.page;
    }

    public String getPagingToken() {
        return this.pagingToken;
    }

    public int getTotal() {
        return this.total;
    }

    @JsonProperty("isFeedFinished")
    public void setIsFeedFinished(boolean z) {
        this.isFeedFinished = z;
    }

    @JsonProperty("page")
    public void setPage(int i) {
        this.page = i;
    }

    @JsonProperty("token")
    public void setPagingToken(String str) {
        this.pagingToken = str;
    }

    @JsonProperty("total")
    public void setTotal(int i) {
        this.total = i;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("PagingInfo(Page:");
        sb.append(this.page);
        sb.append(", Total:");
        sb.append(this.total);
        sb.append(", Token: ");
        return a.t(sb, this.pagingToken, ")");
    }
}
