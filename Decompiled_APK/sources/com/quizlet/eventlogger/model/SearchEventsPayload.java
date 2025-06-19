package com.quizlet.eventlogger.model;

import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.data.model.B1;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SearchEventsPayload {
    private String appSessionId;
    private String correctedQuery;
    private String currentTab;
    private final Long depth;
    private final String emptyStateView;
    private String exerciseId;
    private final Boolean isVerifiedCreatorContent;
    private List<String> orderedShelfList;
    private String originalQuery;

    @NotNull
    private final String platform;

    @NotNull
    private final String query;

    @NotNull
    private final String searchSessionId;
    private final String selectedFilter;
    private Long setId;
    private String studySessionId;
    private String suggestion;
    private List<B1> suggestions;
    private final Long targetObjectId;
    private final String targetObjectType;
    private final Long targetSessionId;
    private String textbookIsbn;
    private Long userCreatorId;
    private Long userId;

    @NotNull
    private final String version;

    public SearchEventsPayload(@NotNull String searchSessionId, @NotNull String query, Long l, Long l2, String str, Long l3, Boolean bool, String str2, String str3) {
        Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
        Intrinsics.checkNotNullParameter(query, "query");
        this.searchSessionId = searchSessionId;
        this.query = query;
        this.depth = l;
        this.targetObjectId = l2;
        this.targetObjectType = str;
        this.targetSessionId = l3;
        this.isVerifiedCreatorContent = bool;
        this.selectedFilter = str2;
        this.emptyStateView = str3;
        this.version = "0.0.7";
        this.platform = "ANDROID";
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SearchEventsPayload)) {
            return false;
        }
        SearchEventsPayload searchEventsPayload = (SearchEventsPayload) obj;
        return Intrinsics.b(this.searchSessionId, searchEventsPayload.searchSessionId) && Intrinsics.b(this.query, searchEventsPayload.query) && Intrinsics.b(this.depth, searchEventsPayload.depth) && Intrinsics.b(this.targetObjectId, searchEventsPayload.targetObjectId) && Intrinsics.b(this.targetObjectType, searchEventsPayload.targetObjectType) && Intrinsics.b(this.targetSessionId, searchEventsPayload.targetSessionId) && Intrinsics.b(this.isVerifiedCreatorContent, searchEventsPayload.isVerifiedCreatorContent) && Intrinsics.b(this.selectedFilter, searchEventsPayload.selectedFilter) && Intrinsics.b(this.emptyStateView, searchEventsPayload.emptyStateView);
    }

    @JsonProperty("app_session_id")
    public final String getAppSessionId() {
        return this.appSessionId;
    }

    @JsonProperty("correctedQuery")
    public final String getCorrectedQuery() {
        return this.correctedQuery;
    }

    @JsonProperty("tab")
    public final String getCurrentTab() {
        return this.currentTab;
    }

    @JsonProperty("depth")
    public final Long getDepth() {
        return this.depth;
    }

    @JsonProperty("empty_state_view")
    public final String getEmptyStateView() {
        return this.emptyStateView;
    }

    @JsonProperty("media_exercise_id")
    public final String getExerciseId() {
        return this.exerciseId;
    }

    @JsonProperty("orderedShelfList")
    public final List<String> getOrderedShelfList() {
        return this.orderedShelfList;
    }

    @JsonProperty("originalQuery")
    public final String getOriginalQuery() {
        return this.originalQuery;
    }

    @JsonProperty("platform")
    @NotNull
    public final String getPlatform() {
        return this.platform;
    }

    @JsonProperty("query")
    @NotNull
    public final String getQuery() {
        return this.query;
    }

    @JsonProperty("search_session_id")
    @NotNull
    public final String getSearchSessionId() {
        return this.searchSessionId;
    }

    @JsonProperty("selectedFilter")
    public final String getSelectedFilter() {
        return this.selectedFilter;
    }

    @JsonProperty("set_id")
    public final Long getSetId() {
        return this.setId;
    }

    @JsonProperty("study_session_id")
    public final String getStudySessionId() {
        return this.studySessionId;
    }

    @JsonProperty("suggestion")
    public final String getSuggestion() {
        return this.suggestion;
    }

    @JsonProperty("suggestions")
    public final List<B1> getSuggestions() {
        return this.suggestions;
    }

    @JsonProperty("target_object_id")
    public final Long getTargetObjectId() {
        return this.targetObjectId;
    }

    @JsonProperty("target_object_type")
    public final String getTargetObjectType() {
        return this.targetObjectType;
    }

    @JsonProperty("target_session_id")
    public final Long getTargetSessionId() {
        return this.targetSessionId;
    }

    @JsonProperty("textbook_isbn")
    public final String getTextbookIsbn() {
        return this.textbookIsbn;
    }

    @JsonProperty("creator_id")
    public final Long getUserCreatorId() {
        return this.userCreatorId;
    }

    @JsonProperty("user_id")
    public final Long getUserId() {
        return this.userId;
    }

    @JsonProperty("version")
    @NotNull
    public final String getVersion() {
        return this.version;
    }

    public final int hashCode() {
        int iE = d0.e(this.searchSessionId.hashCode() * 31, 31, this.query);
        Long l = this.depth;
        int iHashCode = (iE + (l == null ? 0 : l.hashCode())) * 31;
        Long l2 = this.targetObjectId;
        int iHashCode2 = (iHashCode + (l2 == null ? 0 : l2.hashCode())) * 31;
        String str = this.targetObjectType;
        int iHashCode3 = (iHashCode2 + (str == null ? 0 : str.hashCode())) * 31;
        Long l3 = this.targetSessionId;
        int iHashCode4 = (iHashCode3 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Boolean bool = this.isVerifiedCreatorContent;
        int iHashCode5 = (iHashCode4 + (bool == null ? 0 : bool.hashCode())) * 31;
        String str2 = this.selectedFilter;
        int iHashCode6 = (iHashCode5 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.emptyStateView;
        return iHashCode6 + (str3 != null ? str3.hashCode() : 0);
    }

    public final void setAppSessionId(String str) {
        this.appSessionId = str;
    }

    public final void setCorrectedQuery(String str) {
        this.correctedQuery = str;
    }

    public final void setCurrentTab(String str) {
        this.currentTab = str;
    }

    public final void setExerciseId(String str) {
        this.exerciseId = str;
    }

    public final void setOrderedShelfList(List<String> list) {
        this.orderedShelfList = list;
    }

    public final void setOriginalQuery(String str) {
        this.originalQuery = str;
    }

    public final void setSetId(Long l) {
        this.setId = l;
    }

    public final void setStudySessionId(String str) {
        this.studySessionId = str;
    }

    public final void setSuggestion(String str) {
        this.suggestion = str;
    }

    public final void setSuggestions(List<B1> list) {
        this.suggestions = list;
    }

    public final void setTextbookIsbn(String str) {
        this.textbookIsbn = str;
    }

    public final void setUserCreatorId(Long l) {
        this.userCreatorId = l;
    }

    public final void setUserId(Long l) {
        this.userId = l;
    }

    public final String toString() {
        String str = this.searchSessionId;
        String str2 = this.query;
        Long l = this.depth;
        Long l2 = this.targetObjectId;
        String str3 = this.targetObjectType;
        Long l3 = this.targetSessionId;
        Boolean bool = this.isVerifiedCreatorContent;
        String str4 = this.selectedFilter;
        String str5 = this.emptyStateView;
        StringBuilder sbH = AbstractC0147y.h("SearchEventsPayload(searchSessionId=", str, ", query=", str2, ", depth=");
        sbH.append(l);
        sbH.append(", targetObjectId=");
        sbH.append(l2);
        sbH.append(", targetObjectType=");
        sbH.append(str3);
        sbH.append(", targetSessionId=");
        sbH.append(l3);
        sbH.append(", isVerifiedCreatorContent=");
        sbH.append(bool);
        sbH.append(", selectedFilter=");
        sbH.append(str4);
        sbH.append(", emptyStateView=");
        return a.t(sbH, str5, ")");
    }
}
