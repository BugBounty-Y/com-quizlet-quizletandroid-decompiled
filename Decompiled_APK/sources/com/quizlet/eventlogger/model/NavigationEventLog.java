package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.EnumC4503n;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class NavigationEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @JsonProperty("payload")
    @NotNull
    private final Payload payload = new Payload();

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static NavigationEventLog a(boolean z, String screenName, String clickName, String str, String str2) {
            Intrinsics.checkNotNullParameter(screenName, "screenName");
            Intrinsics.checkNotNullParameter(clickName, "clickName");
            NavigationEventLog navigationEventLog = new NavigationEventLog();
            navigationEventLog.setAction(z ? "click" : "show");
            navigationEventLog.getPayload().setScreenName(screenName);
            navigationEventLog.getPayload().setClickName(clickName);
            navigationEventLog.getPayload().setClickCategory(str);
            navigationEventLog.getPayload().setClickSource(str2);
            return navigationEventLog;
        }

        public static /* synthetic */ NavigationEventLog b(Companion companion, boolean z, String str, String str2, String str3) {
            companion.getClass();
            return a(z, str, str2, str3, null);
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("additional_info")
        private AdditionalInfo additionalInfo;

        @JsonProperty("click_category")
        private String clickCategory;

        @JsonProperty("click_name")
        private String clickName;

        @JsonProperty("click_source")
        private String clickSource;

        @JsonProperty("screen_name")
        private String screenName;

        @Metadata
        public static final class AdditionalInfo {

            @JsonProperty("folder_id")
            private Long folderId;

            @JsonProperty("is_expanded")
            private Boolean isExpanded;

            @JsonProperty
            private Boolean isPeerRec;

            @JsonProperty("is_selected")
            private Boolean isSelected;

            @JsonProperty("limit")
            private Integer limit;

            @JsonProperty
            private String studyMaterialId;

            @JsonProperty
            private Integer studyMaterialType;

            @JsonProperty("mode_type")
            private Integer studyMode;

            @JsonProperty("tag")
            private String tagName;

            @JsonProperty("tags_Added")
            private List<String> tagsAdded;

            @JsonProperty("toggled")
            private Boolean toggled;

            public final Long getFolderId() {
                return this.folderId;
            }

            public final Integer getLimit() {
                return this.limit;
            }

            public final String getStudyMaterialId() {
                return this.studyMaterialId;
            }

            public final Integer getStudyMaterialType() {
                return this.studyMaterialType;
            }

            public final Integer getStudyMode() {
                return this.studyMode;
            }

            public final String getTagName() {
                return this.tagName;
            }

            public final List<String> getTagsAdded() {
                return this.tagsAdded;
            }

            public final Boolean getToggled() {
                return this.toggled;
            }

            public final void setExpanded(Boolean bool) {
                this.isExpanded = bool;
            }

            public final void setFolderId(Long l) {
                this.folderId = l;
            }

            public final void setLimit(Integer num) {
                this.limit = num;
            }

            public final void setPeerRec(Boolean bool) {
                this.isPeerRec = bool;
            }

            public final void setSelected(Boolean bool) {
                this.isSelected = bool;
            }

            public final void setStudyMaterialId(String str) {
                this.studyMaterialId = str;
            }

            public final void setStudyMaterialType(Integer num) {
                this.studyMaterialType = num;
            }

            public final void setStudyMode(Integer num) {
                this.studyMode = num;
            }

            public final void setTagName(String str) {
                this.tagName = str;
            }

            public final void setTagsAdded(List<String> list) {
                this.tagsAdded = list;
            }

            public final void setToggled(Boolean bool) {
                this.toggled = bool;
            }
        }

        public final void c(Integer num, String str) {
            AdditionalInfo additionalInfo = this.additionalInfo;
            if (additionalInfo == null) {
                additionalInfo = new AdditionalInfo();
            }
            this.additionalInfo = additionalInfo;
            additionalInfo.setStudyMaterialId(str);
            AdditionalInfo additionalInfo2 = this.additionalInfo;
            if (additionalInfo2 != null) {
                additionalInfo2.setStudyMaterialType(num);
            }
        }

        public final AdditionalInfo getAdditionalInfo() {
            return this.additionalInfo;
        }

        public final String getClickCategory() {
            return this.clickCategory;
        }

        public final String getClickName() {
            return this.clickName;
        }

        public final String getClickSource() {
            return this.clickSource;
        }

        public final String getScreenName() {
            return this.screenName;
        }

        public final void setAdditionalInfo(AdditionalInfo additionalInfo) {
            this.additionalInfo = additionalInfo;
        }

        public final void setClickCategory(String str) {
            this.clickCategory = str;
        }

        public final void setClickName(String str) {
            this.clickName = str;
        }

        public final void setClickSource(String str) {
            this.clickSource = str;
        }

        public final void setFolderId(Long l) {
            AdditionalInfo additionalInfo = this.additionalInfo;
            if (additionalInfo == null) {
                additionalInfo = new AdditionalInfo();
            }
            this.additionalInfo = additionalInfo;
            additionalInfo.setFolderId(l);
        }

        public final void setIsPeerRec(Boolean bool) {
            AdditionalInfo additionalInfo = this.additionalInfo;
            if (additionalInfo == null) {
                additionalInfo = new AdditionalInfo();
            }
            this.additionalInfo = additionalInfo;
            additionalInfo.setPeerRec(bool);
        }

        public final void setLimit(Integer num) {
            AdditionalInfo additionalInfo = this.additionalInfo;
            if (additionalInfo == null) {
                additionalInfo = new AdditionalInfo();
            }
            this.additionalInfo = additionalInfo;
            additionalInfo.setLimit(num);
        }

        public final void setScreenName(String str) {
            this.screenName = str;
        }

        public final void setStudyMode(@NotNull A1 studyMode) {
            Intrinsics.checkNotNullParameter(studyMode, "studyMode");
            AdditionalInfo additionalInfo = this.additionalInfo;
            if (additionalInfo == null) {
                additionalInfo = new AdditionalInfo();
            }
            this.additionalInfo = additionalInfo;
            additionalInfo.setStudyMode(Integer.valueOf(studyMode.a()));
        }

        public final void setTagName(String str) {
            AdditionalInfo additionalInfo = this.additionalInfo;
            if (additionalInfo == null) {
                additionalInfo = new AdditionalInfo();
            }
            this.additionalInfo = additionalInfo;
            additionalInfo.setTagName(str);
        }

        public final void setTagsAdded(List<String> list) {
            AdditionalInfo additionalInfo = this.additionalInfo;
            if (additionalInfo == null) {
                additionalInfo = new AdditionalInfo();
            }
            this.additionalInfo = additionalInfo;
            additionalInfo.setTagsAdded(list);
        }

        public final void setToggled(boolean z) {
            AdditionalInfo additionalInfo = this.additionalInfo;
            if (additionalInfo == null) {
                additionalInfo = new AdditionalInfo();
            }
            this.additionalInfo = additionalInfo;
            additionalInfo.setToggled(Boolean.valueOf(z));
        }
    }

    public NavigationEventLog() {
        setTable(EnumC4503n.NAVIGATION_EVENTS);
    }

    @JsonIgnore
    public final String getClientId() {
        return getPayload().getClientId();
    }

    @JsonIgnore
    public final void setStudyMode(@NotNull A1 studyMode) {
        Intrinsics.checkNotNullParameter(studyMode, "studyMode");
        getPayload().setStudyMode(studyMode);
    }

    @JsonIgnore
    public final void setToggled(boolean z) {
        getPayload().setToggled(z);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
