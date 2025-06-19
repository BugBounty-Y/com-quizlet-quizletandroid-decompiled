package com.quizlet.eventlogger.model;

import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.android.gms.ads.g;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@Metadata
/* loaded from: classes2.dex */
public final class AndroidEventPayload {

    @JsonProperty("app_session_id")
    private String appSessionId;

    @JsonProperty("assigned_rounds")
    private Integer assignedRounds;

    @JsonProperty("client_authentication_provider")
    private String authenticationProvider;

    @JsonProperty("card_style")
    private String cardStyle;

    @JsonProperty("class_id")
    private Long classId;

    @JsonProperty("click_source")
    private String clickSource;

    @JsonProperty("client_model_id")
    private Long clientModelId;

    @JsonProperty("completed_rounds")
    private Integer completedRounds;

    @JsonProperty("courseId")
    private Long courseId;

    @JsonProperty("dedupe_id")
    private String dedupeId;

    @JsonProperty("client_action_depth")
    private Integer depth;

    @JsonProperty("client_device_id")
    private String deviceId;

    @JsonProperty("flashcard_mode")
    private String flashcardMode;

    @JsonProperty("flashcard_response_completed_round")
    private Integer flashcardsNumRoundsCompleted;

    @JsonProperty("flashcard_response_pct_complete")
    private Integer flashcardsPctSwipedOutOfStack;

    @JsonProperty("folder_id")
    private Long folderId;

    @JsonProperty("get_started_items")
    private List<String> getStartedItems;

    @JsonProperty("gms_version")
    private Integer gmsVersion;

    @JsonProperty("client_has_logged_in_before")
    private Boolean hasLoggedInBefore;

    @JsonProperty("is_course_powered")
    private Boolean isCoursePowered;

    @JsonProperty("is_course_recommendation")
    private Boolean isCourseRecommendation;

    @JsonProperty("is_enabled")
    private Boolean isEnabled;

    @JsonProperty("is_landscape")
    private Boolean isLandscape;

    @JsonProperty("is_online")
    private Boolean isOnline;

    @JsonProperty("client_is_sign_up")
    private Boolean isSignUp;

    @JsonProperty("is_whatsapp_share_displayed")
    private Boolean isWhatsAppShareDisplayed;

    @JsonProperty("is_wifi")
    private Boolean isWifi;

    @JsonProperty("isbn")
    private String isbn;

    @JsonProperty("item_order")
    private Integer itemOrder;

    @JsonProperty("location")
    private String location;

    @JsonProperty("mastered")
    private ProgressEventBucketData mastered;

    @JsonProperty("client_message")
    private String message;

    @JsonProperty("mode")
    private Integer mode;

    @JsonProperty(DBOfflineEntityFields.Names.MODEL_TYPE)
    private Integer modelType;

    @JsonProperty("notStudied")
    private ProgressEventBucketData notStudied;

    @JsonProperty("client_previous_screen_name")
    private String previousScreenName;

    @JsonProperty("prompt_side")
    private String promptSide;

    @JsonProperty("remaining_rounds")
    private Integer remainingRounds;

    @JsonProperty(DBGroupFields.Names.SCHOOL_ID)
    private Long schoolId;

    @JsonProperty("client_screen_name")
    private String screenName;

    @JsonProperty("selected_content_identifier")
    private String selectedContentIdentifier;

    @JsonProperty("selected_content_type")
    private String selectedContentType;

    @JsonProperty("server_model_id")
    private Long serverModelId;

    @JsonProperty("client_session_event_counter")
    private Integer sessionEventCounter;

    @JsonProperty("client_session_start_timestamp")
    private Long sessionStartTimestampSec;

    @JsonProperty("set_id")
    private Long setId;

    @JsonProperty("client_subject_size")
    private Integer size;

    @JsonProperty(DBUserFields.Names.USER_UPGRADE_TYPE)
    private String sortType;

    @JsonProperty("sorting")
    private String sorting;

    @JsonProperty("stillLearning")
    private ProgressEventBucketData stillLearning;

    @JsonProperty("study_material_id")
    private String studyMaterialId;

    @JsonProperty("study_material_type")
    private Integer studyMaterialType;

    @JsonProperty("study_session_id")
    private String studySessionId;

    @JsonProperty("tag")
    private String tagName;

    @JsonProperty("path")
    private String urlPath;

    @JsonProperty("client_user_action")
    private String userAction;

    @JsonProperty("client_user_id")
    private Long userId;

    @JsonProperty("user_school_id")
    private Long userSchoolId;

    @JsonProperty("client_username")
    private String username;

    @JsonProperty("client_visit_duration_ms")
    private Long visitDurationMs;

    @JsonProperty("widget_set_url")
    private String widgetUrl;

    public AndroidEventPayload() {
        this(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, -1, 536870911, null);
    }

    public final Boolean a() {
        return this.isLandscape;
    }

    public final Boolean b() {
        return this.isSignUp;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AndroidEventPayload)) {
            return false;
        }
        AndroidEventPayload androidEventPayload = (AndroidEventPayload) obj;
        return Intrinsics.b(this.appSessionId, androidEventPayload.appSessionId) && Intrinsics.b(this.screenName, androidEventPayload.screenName) && Intrinsics.b(this.message, androidEventPayload.message) && Intrinsics.b(this.userId, androidEventPayload.userId) && Intrinsics.b(this.isSignUp, androidEventPayload.isSignUp) && Intrinsics.b(this.username, androidEventPayload.username) && Intrinsics.b(this.authenticationProvider, androidEventPayload.authenticationProvider) && Intrinsics.b(this.hasLoggedInBefore, androidEventPayload.hasLoggedInBefore) && Intrinsics.b(this.deviceId, androidEventPayload.deviceId) && Intrinsics.b(this.visitDurationMs, androidEventPayload.visitDurationMs) && Intrinsics.b(this.previousScreenName, androidEventPayload.previousScreenName) && Intrinsics.b(this.sessionStartTimestampSec, androidEventPayload.sessionStartTimestampSec) && Intrinsics.b(this.sessionEventCounter, androidEventPayload.sessionEventCounter) && Intrinsics.b(this.userAction, androidEventPayload.userAction) && Intrinsics.b(this.depth, androidEventPayload.depth) && Intrinsics.b(this.size, androidEventPayload.size) && Intrinsics.b(this.gmsVersion, androidEventPayload.gmsVersion) && Intrinsics.b(this.isOnline, androidEventPayload.isOnline) && Intrinsics.b(this.isWifi, androidEventPayload.isWifi) && Intrinsics.b(this.modelType, androidEventPayload.modelType) && Intrinsics.b(this.clientModelId, androidEventPayload.clientModelId) && Intrinsics.b(this.serverModelId, androidEventPayload.serverModelId) && Intrinsics.b(this.dedupeId, androidEventPayload.dedupeId) && Intrinsics.b(this.isLandscape, androidEventPayload.isLandscape) && Intrinsics.b(this.cardStyle, androidEventPayload.cardStyle) && Intrinsics.b(this.flashcardMode, androidEventPayload.flashcardMode) && Intrinsics.b(this.flashcardsNumRoundsCompleted, androidEventPayload.flashcardsNumRoundsCompleted) && Intrinsics.b(this.isEnabled, androidEventPayload.isEnabled) && Intrinsics.b(this.isWhatsAppShareDisplayed, androidEventPayload.isWhatsAppShareDisplayed) && Intrinsics.b(this.promptSide, androidEventPayload.promptSide) && Intrinsics.b(this.sorting, androidEventPayload.sorting) && Intrinsics.b(this.flashcardsPctSwipedOutOfStack, androidEventPayload.flashcardsPctSwipedOutOfStack) && Intrinsics.b(this.setId, androidEventPayload.setId) && Intrinsics.b(this.classId, androidEventPayload.classId) && Intrinsics.b(this.folderId, androidEventPayload.folderId) && Intrinsics.b(this.location, androidEventPayload.location) && Intrinsics.b(this.courseId, androidEventPayload.courseId) && Intrinsics.b(this.schoolId, androidEventPayload.schoolId) && Intrinsics.b(this.userSchoolId, androidEventPayload.userSchoolId) && Intrinsics.b(this.isbn, androidEventPayload.isbn) && Intrinsics.b(this.itemOrder, androidEventPayload.itemOrder) && Intrinsics.b(this.selectedContentIdentifier, androidEventPayload.selectedContentIdentifier) && Intrinsics.b(this.selectedContentType, androidEventPayload.selectedContentType) && Intrinsics.b(this.studySessionId, androidEventPayload.studySessionId) && Intrinsics.b(this.mode, androidEventPayload.mode) && Intrinsics.b(this.remainingRounds, androidEventPayload.remainingRounds) && Intrinsics.b(this.completedRounds, androidEventPayload.completedRounds) && Intrinsics.b(this.assignedRounds, androidEventPayload.assignedRounds) && Intrinsics.b(this.notStudied, androidEventPayload.notStudied) && Intrinsics.b(this.stillLearning, androidEventPayload.stillLearning) && Intrinsics.b(this.mastered, androidEventPayload.mastered) && Intrinsics.b(this.getStartedItems, androidEventPayload.getStartedItems) && Intrinsics.b(this.urlPath, androidEventPayload.urlPath) && Intrinsics.b(this.widgetUrl, androidEventPayload.widgetUrl) && Intrinsics.b(this.studyMaterialType, androidEventPayload.studyMaterialType) && Intrinsics.b(this.studyMaterialId, androidEventPayload.studyMaterialId) && Intrinsics.b(this.isCoursePowered, androidEventPayload.isCoursePowered) && Intrinsics.b(this.isCourseRecommendation, androidEventPayload.isCourseRecommendation) && Intrinsics.b(this.sortType, androidEventPayload.sortType) && Intrinsics.b(this.tagName, androidEventPayload.tagName) && Intrinsics.b(this.clickSource, androidEventPayload.clickSource);
    }

    public final String getAppSessionId() {
        return this.appSessionId;
    }

    public final Integer getAssignedRounds() {
        return this.assignedRounds;
    }

    public final String getAuthenticationProvider() {
        return this.authenticationProvider;
    }

    public final String getCardStyle() {
        return this.cardStyle;
    }

    public final Long getClassId() {
        return this.classId;
    }

    public final String getClickSource() {
        return this.clickSource;
    }

    public final Long getClientModelId() {
        return this.clientModelId;
    }

    public final Integer getCompletedRounds() {
        return this.completedRounds;
    }

    public final Long getCourseId() {
        return this.courseId;
    }

    public final String getDedupeId() {
        return this.dedupeId;
    }

    public final Integer getDepth() {
        return this.depth;
    }

    public final String getDeviceId() {
        return this.deviceId;
    }

    public final String getFlashcardMode() {
        return this.flashcardMode;
    }

    public final Integer getFlashcardsNumRoundsCompleted() {
        return this.flashcardsNumRoundsCompleted;
    }

    public final Integer getFlashcardsPctSwipedOutOfStack() {
        return this.flashcardsPctSwipedOutOfStack;
    }

    public final Long getFolderId() {
        return this.folderId;
    }

    public final List<String> getGetStartedItems() {
        return this.getStartedItems;
    }

    public final Integer getGmsVersion() {
        return this.gmsVersion;
    }

    public final Boolean getHasLoggedInBefore() {
        return this.hasLoggedInBefore;
    }

    public final String getIsbn() {
        return this.isbn;
    }

    public final Integer getItemOrder() {
        return this.itemOrder;
    }

    public final String getLocation() {
        return this.location;
    }

    public final ProgressEventBucketData getMastered() {
        return this.mastered;
    }

    public final String getMessage() {
        return this.message;
    }

    public final Integer getMode() {
        return this.mode;
    }

    public final Integer getModelType() {
        return this.modelType;
    }

    public final ProgressEventBucketData getNotStudied() {
        return this.notStudied;
    }

    public final String getPreviousScreenName() {
        return this.previousScreenName;
    }

    public final String getPromptSide() {
        return this.promptSide;
    }

    public final Integer getRemainingRounds() {
        return this.remainingRounds;
    }

    public final Long getSchoolId() {
        return this.schoolId;
    }

    public final String getScreenName() {
        return this.screenName;
    }

    public final String getSelectedContentIdentifier() {
        return this.selectedContentIdentifier;
    }

    public final String getSelectedContentType() {
        return this.selectedContentType;
    }

    public final Long getServerModelId() {
        return this.serverModelId;
    }

    public final Integer getSessionEventCounter() {
        return this.sessionEventCounter;
    }

    public final Long getSessionStartTimestampSec() {
        return this.sessionStartTimestampSec;
    }

    public final Long getSetId() {
        return this.setId;
    }

    public final Integer getSize() {
        return this.size;
    }

    public final String getSortType() {
        return this.sortType;
    }

    public final String getSorting() {
        return this.sorting;
    }

    public final ProgressEventBucketData getStillLearning() {
        return this.stillLearning;
    }

    public final String getStudyMaterialId() {
        return this.studyMaterialId;
    }

    public final Integer getStudyMaterialType() {
        return this.studyMaterialType;
    }

    public final String getStudySessionId() {
        return this.studySessionId;
    }

    public final String getTagName() {
        return this.tagName;
    }

    public final String getUrlPath() {
        return this.urlPath;
    }

    public final String getUserAction() {
        return this.userAction;
    }

    public final Long getUserId() {
        return this.userId;
    }

    public final Long getUserSchoolId() {
        return this.userSchoolId;
    }

    public final String getUsername() {
        return this.username;
    }

    public final Long getVisitDurationMs() {
        return this.visitDurationMs;
    }

    public final String getWidgetUrl() {
        return this.widgetUrl;
    }

    public final int hashCode() {
        String str = this.appSessionId;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.screenName;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.message;
        int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
        Long l = this.userId;
        int iHashCode4 = (iHashCode3 + (l == null ? 0 : l.hashCode())) * 31;
        Boolean bool = this.isSignUp;
        int iHashCode5 = (iHashCode4 + (bool == null ? 0 : bool.hashCode())) * 31;
        String str4 = this.username;
        int iHashCode6 = (iHashCode5 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.authenticationProvider;
        int iHashCode7 = (iHashCode6 + (str5 == null ? 0 : str5.hashCode())) * 31;
        Boolean bool2 = this.hasLoggedInBefore;
        int iHashCode8 = (iHashCode7 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        String str6 = this.deviceId;
        int iHashCode9 = (iHashCode8 + (str6 == null ? 0 : str6.hashCode())) * 31;
        Long l2 = this.visitDurationMs;
        int iHashCode10 = (iHashCode9 + (l2 == null ? 0 : l2.hashCode())) * 31;
        String str7 = this.previousScreenName;
        int iHashCode11 = (iHashCode10 + (str7 == null ? 0 : str7.hashCode())) * 31;
        Long l3 = this.sessionStartTimestampSec;
        int iHashCode12 = (iHashCode11 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Integer num = this.sessionEventCounter;
        int iHashCode13 = (iHashCode12 + (num == null ? 0 : num.hashCode())) * 31;
        String str8 = this.userAction;
        int iHashCode14 = (iHashCode13 + (str8 == null ? 0 : str8.hashCode())) * 31;
        Integer num2 = this.depth;
        int iHashCode15 = (iHashCode14 + (num2 == null ? 0 : num2.hashCode())) * 31;
        Integer num3 = this.size;
        int iHashCode16 = (iHashCode15 + (num3 == null ? 0 : num3.hashCode())) * 31;
        Integer num4 = this.gmsVersion;
        int iHashCode17 = (iHashCode16 + (num4 == null ? 0 : num4.hashCode())) * 31;
        Boolean bool3 = this.isOnline;
        int iHashCode18 = (iHashCode17 + (bool3 == null ? 0 : bool3.hashCode())) * 31;
        Boolean bool4 = this.isWifi;
        int iHashCode19 = (iHashCode18 + (bool4 == null ? 0 : bool4.hashCode())) * 31;
        Integer num5 = this.modelType;
        int iHashCode20 = (iHashCode19 + (num5 == null ? 0 : num5.hashCode())) * 31;
        Long l4 = this.clientModelId;
        int iHashCode21 = (iHashCode20 + (l4 == null ? 0 : l4.hashCode())) * 31;
        Long l5 = this.serverModelId;
        int iHashCode22 = (iHashCode21 + (l5 == null ? 0 : l5.hashCode())) * 31;
        String str9 = this.dedupeId;
        int iHashCode23 = (iHashCode22 + (str9 == null ? 0 : str9.hashCode())) * 31;
        Boolean bool5 = this.isLandscape;
        int iHashCode24 = (iHashCode23 + (bool5 == null ? 0 : bool5.hashCode())) * 31;
        String str10 = this.cardStyle;
        int iHashCode25 = (iHashCode24 + (str10 == null ? 0 : str10.hashCode())) * 31;
        String str11 = this.flashcardMode;
        int iHashCode26 = (iHashCode25 + (str11 == null ? 0 : str11.hashCode())) * 31;
        Integer num6 = this.flashcardsNumRoundsCompleted;
        int iHashCode27 = (iHashCode26 + (num6 == null ? 0 : num6.hashCode())) * 31;
        Boolean bool6 = this.isEnabled;
        int iHashCode28 = (iHashCode27 + (bool6 == null ? 0 : bool6.hashCode())) * 31;
        Boolean bool7 = this.isWhatsAppShareDisplayed;
        int iHashCode29 = (iHashCode28 + (bool7 == null ? 0 : bool7.hashCode())) * 31;
        String str12 = this.promptSide;
        int iHashCode30 = (iHashCode29 + (str12 == null ? 0 : str12.hashCode())) * 31;
        String str13 = this.sorting;
        int iHashCode31 = (iHashCode30 + (str13 == null ? 0 : str13.hashCode())) * 31;
        Integer num7 = this.flashcardsPctSwipedOutOfStack;
        int iHashCode32 = (iHashCode31 + (num7 == null ? 0 : num7.hashCode())) * 31;
        Long l6 = this.setId;
        int iHashCode33 = (iHashCode32 + (l6 == null ? 0 : l6.hashCode())) * 31;
        Long l7 = this.classId;
        int iHashCode34 = (iHashCode33 + (l7 == null ? 0 : l7.hashCode())) * 31;
        Long l8 = this.folderId;
        int iHashCode35 = (iHashCode34 + (l8 == null ? 0 : l8.hashCode())) * 31;
        String str14 = this.location;
        int iHashCode36 = (iHashCode35 + (str14 == null ? 0 : str14.hashCode())) * 31;
        Long l9 = this.courseId;
        int iHashCode37 = (iHashCode36 + (l9 == null ? 0 : l9.hashCode())) * 31;
        Long l10 = this.schoolId;
        int iHashCode38 = (iHashCode37 + (l10 == null ? 0 : l10.hashCode())) * 31;
        Long l11 = this.userSchoolId;
        int iHashCode39 = (iHashCode38 + (l11 == null ? 0 : l11.hashCode())) * 31;
        String str15 = this.isbn;
        int iHashCode40 = (iHashCode39 + (str15 == null ? 0 : str15.hashCode())) * 31;
        Integer num8 = this.itemOrder;
        int iHashCode41 = (iHashCode40 + (num8 == null ? 0 : num8.hashCode())) * 31;
        String str16 = this.selectedContentIdentifier;
        int iHashCode42 = (iHashCode41 + (str16 == null ? 0 : str16.hashCode())) * 31;
        String str17 = this.selectedContentType;
        int iHashCode43 = (iHashCode42 + (str17 == null ? 0 : str17.hashCode())) * 31;
        String str18 = this.studySessionId;
        int iHashCode44 = (iHashCode43 + (str18 == null ? 0 : str18.hashCode())) * 31;
        Integer num9 = this.mode;
        int iHashCode45 = (iHashCode44 + (num9 == null ? 0 : num9.hashCode())) * 31;
        Integer num10 = this.remainingRounds;
        int iHashCode46 = (iHashCode45 + (num10 == null ? 0 : num10.hashCode())) * 31;
        Integer num11 = this.completedRounds;
        int iHashCode47 = (iHashCode46 + (num11 == null ? 0 : num11.hashCode())) * 31;
        Integer num12 = this.assignedRounds;
        int iHashCode48 = (iHashCode47 + (num12 == null ? 0 : num12.hashCode())) * 31;
        ProgressEventBucketData progressEventBucketData = this.notStudied;
        int iHashCode49 = (iHashCode48 + (progressEventBucketData == null ? 0 : progressEventBucketData.hashCode())) * 31;
        ProgressEventBucketData progressEventBucketData2 = this.stillLearning;
        int iHashCode50 = (iHashCode49 + (progressEventBucketData2 == null ? 0 : progressEventBucketData2.hashCode())) * 31;
        ProgressEventBucketData progressEventBucketData3 = this.mastered;
        int iHashCode51 = (iHashCode50 + (progressEventBucketData3 == null ? 0 : progressEventBucketData3.hashCode())) * 31;
        List<String> list = this.getStartedItems;
        int iHashCode52 = (iHashCode51 + (list == null ? 0 : list.hashCode())) * 31;
        String str19 = this.urlPath;
        int iHashCode53 = (iHashCode52 + (str19 == null ? 0 : str19.hashCode())) * 31;
        String str20 = this.widgetUrl;
        int iHashCode54 = (iHashCode53 + (str20 == null ? 0 : str20.hashCode())) * 31;
        Integer num13 = this.studyMaterialType;
        int iHashCode55 = (iHashCode54 + (num13 == null ? 0 : num13.hashCode())) * 31;
        String str21 = this.studyMaterialId;
        int iHashCode56 = (iHashCode55 + (str21 == null ? 0 : str21.hashCode())) * 31;
        Boolean bool8 = this.isCoursePowered;
        int iHashCode57 = (iHashCode56 + (bool8 == null ? 0 : bool8.hashCode())) * 31;
        Boolean bool9 = this.isCourseRecommendation;
        int iHashCode58 = (iHashCode57 + (bool9 == null ? 0 : bool9.hashCode())) * 31;
        String str22 = this.sortType;
        int iHashCode59 = (iHashCode58 + (str22 == null ? 0 : str22.hashCode())) * 31;
        String str23 = this.tagName;
        int iHashCode60 = (iHashCode59 + (str23 == null ? 0 : str23.hashCode())) * 31;
        String str24 = this.clickSource;
        return iHashCode60 + (str24 != null ? str24.hashCode() : 0);
    }

    public final void setAppSessionId(String str) {
        this.appSessionId = str;
    }

    public final void setAssignedRounds(Integer num) {
        this.assignedRounds = num;
    }

    public final void setAuthenticationProvider(String str) {
        this.authenticationProvider = str;
    }

    public final void setCardStyle(String str) {
        this.cardStyle = str;
    }

    public final void setClassId(Long l) {
        this.classId = l;
    }

    public final void setClickSource(String str) {
        this.clickSource = str;
    }

    public final void setClientModelId(Long l) {
        this.clientModelId = l;
    }

    public final void setCompletedRounds(Integer num) {
        this.completedRounds = num;
    }

    public final void setCourseId(Long l) {
        this.courseId = l;
    }

    public final void setCoursePowered(Boolean bool) {
        this.isCoursePowered = bool;
    }

    public final void setCourseRecommendation(Boolean bool) {
        this.isCourseRecommendation = bool;
    }

    public final void setDedupeId(String str) {
        this.dedupeId = str;
    }

    public final void setDepth(Integer num) {
        this.depth = num;
    }

    public final void setDeviceId(String str) {
        this.deviceId = str;
    }

    public final void setEnabled(Boolean bool) {
        this.isEnabled = bool;
    }

    public final void setFlashcardMode(String str) {
        this.flashcardMode = str;
    }

    public final void setFlashcardsNumRoundsCompleted(Integer num) {
        this.flashcardsNumRoundsCompleted = num;
    }

    public final void setFlashcardsPctSwipedOutOfStack(Integer num) {
        this.flashcardsPctSwipedOutOfStack = num;
    }

    public final void setFolderId(Long l) {
        this.folderId = l;
    }

    public final void setGetStartedItems(List<String> list) {
        this.getStartedItems = list;
    }

    public final void setGmsVersion(Integer num) {
        this.gmsVersion = num;
    }

    public final void setHasLoggedInBefore(Boolean bool) {
        this.hasLoggedInBefore = bool;
    }

    public final void setIsbn(String str) {
        this.isbn = str;
    }

    public final void setItemOrder(Integer num) {
        this.itemOrder = num;
    }

    public final void setLandscape(Boolean bool) {
        this.isLandscape = bool;
    }

    public final void setLocation(String str) {
        this.location = str;
    }

    public final void setMastered(ProgressEventBucketData progressEventBucketData) {
        this.mastered = progressEventBucketData;
    }

    public final void setMessage(String str) {
        this.message = str;
    }

    public final void setMode(Integer num) {
        this.mode = num;
    }

    public final void setModelType(Integer num) {
        this.modelType = num;
    }

    public final void setNotStudied(ProgressEventBucketData progressEventBucketData) {
        this.notStudied = progressEventBucketData;
    }

    public final void setOnline(Boolean bool) {
        this.isOnline = bool;
    }

    public final void setPreviousScreenName(String str) {
        this.previousScreenName = str;
    }

    public final void setPromptSide(String str) {
        this.promptSide = str;
    }

    public final void setRemainingRounds(Integer num) {
        this.remainingRounds = num;
    }

    public final void setSchoolId(Long l) {
        this.schoolId = l;
    }

    public final void setScreenName(String str) {
        this.screenName = str;
    }

    public final void setSelectedContentIdentifier(String str) {
        this.selectedContentIdentifier = str;
    }

    public final void setSelectedContentType(String str) {
        this.selectedContentType = str;
    }

    public final void setServerModelId(Long l) {
        this.serverModelId = l;
    }

    public final void setSessionEventCounter(Integer num) {
        this.sessionEventCounter = num;
    }

    public final void setSessionStartTimestampSec(Long l) {
        this.sessionStartTimestampSec = l;
    }

    public final void setSetId(Long l) {
        this.setId = l;
    }

    public final void setSignUp(Boolean bool) {
        this.isSignUp = bool;
    }

    public final void setSize(Integer num) {
        this.size = num;
    }

    public final void setSortType(String str) {
        this.sortType = str;
    }

    public final void setSorting(String str) {
        this.sorting = str;
    }

    public final void setStillLearning(ProgressEventBucketData progressEventBucketData) {
        this.stillLearning = progressEventBucketData;
    }

    public final void setStudyMaterialId(String str) {
        this.studyMaterialId = str;
    }

    public final void setStudyMaterialType(Integer num) {
        this.studyMaterialType = num;
    }

    public final void setStudySessionId(String str) {
        this.studySessionId = str;
    }

    public final void setTagName(String str) {
        this.tagName = str;
    }

    public final void setUrlPath(String str) {
        this.urlPath = str;
    }

    public final void setUserAction(String str) {
        this.userAction = str;
    }

    public final void setUserId(Long l) {
        this.userId = l;
    }

    public final void setUserSchoolId(Long l) {
        this.userSchoolId = l;
    }

    public final void setUsername(String str) {
        this.username = str;
    }

    public final void setVisitDurationMs(Long l) {
        this.visitDurationMs = l;
    }

    public final void setWhatsAppShareDisplayed(Boolean bool) {
        this.isWhatsAppShareDisplayed = bool;
    }

    public final void setWidgetUrl(String str) {
        this.widgetUrl = str;
    }

    public final void setWifi(Boolean bool) {
        this.isWifi = bool;
    }

    public final String toString() {
        String str = this.appSessionId;
        String str2 = this.screenName;
        String str3 = this.message;
        Long l = this.userId;
        Boolean bool = this.isSignUp;
        String str4 = this.username;
        String str5 = this.authenticationProvider;
        Boolean bool2 = this.hasLoggedInBefore;
        String str6 = this.deviceId;
        Long l2 = this.visitDurationMs;
        String str7 = this.previousScreenName;
        Long l3 = this.sessionStartTimestampSec;
        Integer num = this.sessionEventCounter;
        String str8 = this.userAction;
        Integer num2 = this.depth;
        Integer num3 = this.size;
        Integer num4 = this.gmsVersion;
        Boolean bool3 = this.isOnline;
        Boolean bool4 = this.isWifi;
        Integer num5 = this.modelType;
        Long l4 = this.clientModelId;
        Long l5 = this.serverModelId;
        String str9 = this.dedupeId;
        Boolean bool5 = this.isLandscape;
        String str10 = this.cardStyle;
        String str11 = this.flashcardMode;
        Integer num6 = this.flashcardsNumRoundsCompleted;
        Boolean bool6 = this.isEnabled;
        Boolean bool7 = this.isWhatsAppShareDisplayed;
        String str12 = this.promptSide;
        String str13 = this.sorting;
        Integer num7 = this.flashcardsPctSwipedOutOfStack;
        Long l6 = this.setId;
        Long l7 = this.classId;
        Long l8 = this.folderId;
        String str14 = this.location;
        Long l9 = this.courseId;
        Long l10 = this.schoolId;
        Long l11 = this.userSchoolId;
        String str15 = this.isbn;
        Integer num8 = this.itemOrder;
        String str16 = this.selectedContentIdentifier;
        String str17 = this.selectedContentType;
        String str18 = this.studySessionId;
        Integer num9 = this.mode;
        Integer num10 = this.remainingRounds;
        Integer num11 = this.completedRounds;
        Integer num12 = this.assignedRounds;
        ProgressEventBucketData progressEventBucketData = this.notStudied;
        ProgressEventBucketData progressEventBucketData2 = this.stillLearning;
        ProgressEventBucketData progressEventBucketData3 = this.mastered;
        List<String> list = this.getStartedItems;
        String str19 = this.urlPath;
        String str20 = this.widgetUrl;
        Integer num13 = this.studyMaterialType;
        String str21 = this.studyMaterialId;
        Boolean bool8 = this.isCoursePowered;
        Boolean bool9 = this.isCourseRecommendation;
        String str22 = this.sortType;
        String str23 = this.tagName;
        String str24 = this.clickSource;
        StringBuilder sbH = AbstractC0147y.h("AndroidEventPayload(appSessionId=", str, ", screenName=", str2, ", message=");
        sbH.append(str3);
        sbH.append(", userId=");
        sbH.append(l);
        sbH.append(", isSignUp=");
        sbH.append(bool);
        sbH.append(", username=");
        sbH.append(str4);
        sbH.append(", authenticationProvider=");
        sbH.append(str5);
        sbH.append(", hasLoggedInBefore=");
        sbH.append(bool2);
        sbH.append(", deviceId=");
        sbH.append(str6);
        sbH.append(", visitDurationMs=");
        sbH.append(l2);
        sbH.append(", previousScreenName=");
        sbH.append(str7);
        sbH.append(", sessionStartTimestampSec=");
        sbH.append(l3);
        sbH.append(", sessionEventCounter=");
        sbH.append(num);
        sbH.append(", userAction=");
        sbH.append(str8);
        sbH.append(", depth=");
        sbH.append(num2);
        sbH.append(", size=");
        sbH.append(num3);
        sbH.append(", gmsVersion=");
        sbH.append(num4);
        sbH.append(", isOnline=");
        sbH.append(bool3);
        sbH.append(", isWifi=");
        sbH.append(bool4);
        sbH.append(", modelType=");
        sbH.append(num5);
        sbH.append(", clientModelId=");
        sbH.append(l4);
        sbH.append(", serverModelId=");
        sbH.append(l5);
        sbH.append(", dedupeId=");
        sbH.append(str9);
        sbH.append(", isLandscape=");
        sbH.append(bool5);
        sbH.append(", cardStyle=");
        B.u(sbH, str10, ", flashcardMode=", str11, ", flashcardsNumRoundsCompleted=");
        sbH.append(num6);
        sbH.append(", isEnabled=");
        sbH.append(bool6);
        sbH.append(", isWhatsAppShareDisplayed=");
        sbH.append(bool7);
        sbH.append(", promptSide=");
        sbH.append(str12);
        sbH.append(", sorting=");
        sbH.append(str13);
        sbH.append(", flashcardsPctSwipedOutOfStack=");
        sbH.append(num7);
        sbH.append(", setId=");
        sbH.append(l6);
        sbH.append(", classId=");
        sbH.append(l7);
        sbH.append(", folderId=");
        sbH.append(l8);
        sbH.append(", location=");
        sbH.append(str14);
        sbH.append(", courseId=");
        sbH.append(l9);
        sbH.append(", schoolId=");
        sbH.append(l10);
        sbH.append(", userSchoolId=");
        sbH.append(l11);
        sbH.append(", isbn=");
        sbH.append(str15);
        sbH.append(", itemOrder=");
        sbH.append(num8);
        sbH.append(", selectedContentIdentifier=");
        sbH.append(str16);
        sbH.append(", selectedContentType=");
        B.u(sbH, str17, ", studySessionId=", str18, ", mode=");
        sbH.append(num9);
        sbH.append(", remainingRounds=");
        sbH.append(num10);
        sbH.append(", completedRounds=");
        sbH.append(num11);
        sbH.append(", assignedRounds=");
        sbH.append(num12);
        sbH.append(", notStudied=");
        sbH.append(progressEventBucketData);
        sbH.append(", stillLearning=");
        sbH.append(progressEventBucketData2);
        sbH.append(", mastered=");
        sbH.append(progressEventBucketData3);
        sbH.append(", getStartedItems=");
        sbH.append(list);
        sbH.append(", urlPath=");
        B.u(sbH, str19, ", widgetUrl=", str20, ", studyMaterialType=");
        sbH.append(num13);
        sbH.append(", studyMaterialId=");
        sbH.append(str21);
        sbH.append(", isCoursePowered=");
        sbH.append(bool8);
        sbH.append(", isCourseRecommendation=");
        sbH.append(bool9);
        sbH.append(", sortType=");
        B.u(sbH, str22, ", tagName=", str23, ", clickSource=");
        return a.t(sbH, str24, ")");
    }

    public AndroidEventPayload(String str, String str2, String str3, Long l, Boolean bool, String str4, String str5, Boolean bool2, String str6, Long l2, String str7, Long l3, Integer num, String str8, Integer num2, Integer num3, Integer num4, Boolean bool3, Boolean bool4, Integer num5, Long l4, Long l5, String str9, Boolean bool5, String str10, String str11, Integer num6, Boolean bool6, Boolean bool7, String str12, String str13, Integer num7, Long l6, Long l7, Long l8, String str14, Long l9, Long l10, Long l11, String str15, Integer num8, String str16, String str17, String str18, Integer num9, Integer num10, Integer num11, Integer num12, ProgressEventBucketData progressEventBucketData, ProgressEventBucketData progressEventBucketData2, ProgressEventBucketData progressEventBucketData3, List<String> list, String str19, String str20, Integer num13, String str21, Boolean bool8, Boolean bool9, String str22, String str23, String str24) {
        this.appSessionId = str;
        this.screenName = str2;
        this.message = str3;
        this.userId = l;
        this.isSignUp = bool;
        this.username = str4;
        this.authenticationProvider = str5;
        this.hasLoggedInBefore = bool2;
        this.deviceId = str6;
        this.visitDurationMs = l2;
        this.previousScreenName = str7;
        this.sessionStartTimestampSec = l3;
        this.sessionEventCounter = num;
        this.userAction = str8;
        this.depth = num2;
        this.size = num3;
        this.gmsVersion = num4;
        this.isOnline = bool3;
        this.isWifi = bool4;
        this.modelType = num5;
        this.clientModelId = l4;
        this.serverModelId = l5;
        this.dedupeId = str9;
        this.isLandscape = bool5;
        this.cardStyle = str10;
        this.flashcardMode = str11;
        this.flashcardsNumRoundsCompleted = num6;
        this.isEnabled = bool6;
        this.isWhatsAppShareDisplayed = bool7;
        this.promptSide = str12;
        this.sorting = str13;
        this.flashcardsPctSwipedOutOfStack = num7;
        this.setId = l6;
        this.classId = l7;
        this.folderId = l8;
        this.location = str14;
        this.courseId = l9;
        this.schoolId = l10;
        this.userSchoolId = l11;
        this.isbn = str15;
        this.itemOrder = num8;
        this.selectedContentIdentifier = str16;
        this.selectedContentType = str17;
        this.studySessionId = str18;
        this.mode = num9;
        this.remainingRounds = num10;
        this.completedRounds = num11;
        this.assignedRounds = num12;
        this.notStudied = progressEventBucketData;
        this.stillLearning = progressEventBucketData2;
        this.mastered = progressEventBucketData3;
        this.getStartedItems = list;
        this.urlPath = str19;
        this.widgetUrl = str20;
        this.studyMaterialType = num13;
        this.studyMaterialId = str21;
        this.isCoursePowered = bool8;
        this.isCourseRecommendation = bool9;
        this.sortType = str22;
        this.tagName = str23;
        this.clickSource = str24;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public /* synthetic */ AndroidEventPayload(String str, String str2, String str3, Long l, Boolean bool, String str4, String str5, Boolean bool2, String str6, Long l2, String str7, Long l3, Integer num, String str8, Integer num2, Integer num3, Integer num4, Boolean bool3, Boolean bool4, Integer num5, Long l4, Long l5, String str9, Boolean bool5, String str10, String str11, Integer num6, Boolean bool6, Boolean bool7, String str12, String str13, Integer num7, Long l6, Long l7, Long l8, String str14, Long l9, Long l10, Long l11, String str15, Integer num8, String str16, String str17, String str18, Integer num9, Integer num10, Integer num11, Integer num12, ProgressEventBucketData progressEventBucketData, ProgressEventBucketData progressEventBucketData2, ProgressEventBucketData progressEventBucketData3, List list, String str19, String str20, Integer num13, String str21, Boolean bool8, Boolean bool9, String str22, String str23, String str24, int i, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        String str25 = (i & 1) != 0 ? null : str;
        this(str25, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : str3, (i & 8) != 0 ? null : l, (i & 16) != 0 ? null : bool, (i & 32) != 0 ? null : str4, (i & 64) != 0 ? null : str5, (i & 128) != 0 ? null : bool2, (i & 256) != 0 ? null : str6, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : l2, (i & 1024) != 0 ? null : str7, (i & 2048) != 0 ? null : l3, (i & 4096) != 0 ? null : num, (i & 8192) != 0 ? null : str8, (i & 16384) != 0 ? null : num2, (i & 32768) != 0 ? null : num3, (i & 65536) != 0 ? null : num4, (i & 131072) != 0 ? null : bool3, (i & 262144) != 0 ? null : bool4, (i & 524288) != 0 ? null : num5, (i & 1048576) != 0 ? null : l4, (i & 2097152) != 0 ? null : l5, (i & 4194304) != 0 ? null : str9, (i & 8388608) != 0 ? null : bool5, (i & 16777216) != 0 ? null : str10, (i & 33554432) != 0 ? null : str11, (i & 67108864) != 0 ? null : num6, (i & 134217728) != 0 ? null : bool6, (i & 268435456) != 0 ? null : bool7, (i & 536870912) != 0 ? null : str12, (i & 1073741824) != 0 ? null : str13, (i & Integer.MIN_VALUE) != 0 ? null : num7, (i2 & 1) != 0 ? null : l6, (i2 & 2) != 0 ? null : l7, (i2 & 4) != 0 ? null : l8, (i2 & 8) != 0 ? null : str14, (i2 & 16) != 0 ? null : l9, (i2 & 32) != 0 ? null : l10, (i2 & 64) != 0 ? null : l11, (i2 & 128) != 0 ? null : str15, (i2 & 256) != 0 ? null : num8, (i2 & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : str16, (i2 & 1024) != 0 ? null : str17, (i2 & 2048) != 0 ? null : str18, (i2 & 4096) != 0 ? null : num9, (i2 & 8192) != 0 ? null : num10, (i2 & 16384) != 0 ? null : num11, (i2 & 32768) != 0 ? null : num12, (i2 & 65536) != 0 ? null : progressEventBucketData, (i2 & 131072) != 0 ? null : progressEventBucketData2, (i2 & 262144) != 0 ? null : progressEventBucketData3, (i2 & 524288) != 0 ? null : list, (i2 & 1048576) != 0 ? null : str19, (i2 & 2097152) != 0 ? null : str20, (i2 & 4194304) != 0 ? null : num13, (i2 & 8388608) != 0 ? null : str21, (i2 & 16777216) != 0 ? null : bool8, (i2 & 33554432) != 0 ? null : bool9, (i2 & 67108864) != 0 ? null : str22, (i2 & 134217728) != 0 ? null : str23, (i2 & 268435456) != 0 ? null : str24);
    }
}
