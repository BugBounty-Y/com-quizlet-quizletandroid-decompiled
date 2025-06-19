package com.quizlet.eventlogger.features.search;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.eventlogger.events.CurrentUserEvent;
import com.quizlet.eventlogger.model.EventLog;
import com.quizlet.eventlogger.model.SearchEventsPayload;
import com.quizlet.generated.enums.EnumC4472c1;
import com.quizlet.generated.enums.EnumC4478e1;
import com.quizlet.generated.enums.EnumC4503n;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.enums.a;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SearchEventsEventLog extends EventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final SearchEventsPayload payload;

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    @Metadata
    public static final class Action {
        private static final /* synthetic */ a $ENTRIES;
        private static final /* synthetic */ Action[] $VALUES;
        public static final Action a;
        public static final Action b;
        public static final Action c;
        public static final Action d;

        @NotNull
        private final String eventString;

        static {
            Action action = new Action("SEARCH_EXIT", 0, "SEARCH_EXIT");
            a = action;
            Action action2 = new Action("CLICK_STUDY_SET_PREVIEW", 1, "CLICK_STUDY_SET_PREVIEW");
            b = action2;
            Action action3 = new Action("SEARCH_SUBMITTED", 2, "search_submitted");
            c = action3;
            Action action4 = new Action("SEARCH_CLEAR_QUERY", 3, "search_clear_query");
            d = action4;
            Action[] actionArr = {action, action2, action3, action4};
            $VALUES = actionArr;
            $ENTRIES = AbstractC3328d.f(actionArr);
        }

        private Action(String str, int i, String str2) {
            this.eventString = str2;
        }

        @NotNull
        public static a getEntries() {
            return $ENTRIES;
        }

        public static Action valueOf(String str) {
            return (Action) Enum.valueOf(Action.class, str);
        }

        public static Action[] values() {
            return (Action[]) $VALUES.clone();
        }

        @NotNull
        public final String getEventString() {
            return this.eventString;
        }
    }

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static SearchEventsEventLog a(Companion companion, String searchSessionId, String action, String query, Long l, Long l2, EnumC4478e1 enumC4478e1, Long l3, Boolean bool, String str, String str2, Long l4, String str3, String str4, int i) {
            Long l5 = (i & 8) != 0 ? null : l;
            Long l6 = (i & 16) != 0 ? null : l2;
            EnumC4478e1 enumC4478e12 = (i & 32) != 0 ? null : enumC4478e1;
            Long l7 = (i & 64) != 0 ? null : l3;
            Boolean bool2 = (i & 128) != 0 ? null : bool;
            String str5 = (i & 256) != 0 ? null : str;
            String str6 = (i & 1024) != 0 ? null : str2;
            Long l8 = (i & 2048) != 0 ? null : l4;
            String str7 = (i & 4096) != 0 ? null : str3;
            String str8 = (i & 8192) != 0 ? null : str4;
            companion.getClass();
            Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(query, "query");
            SearchEventsPayload searchEventsPayload = new SearchEventsPayload(searchSessionId, query, l5, l6, enumC4478e12 != null ? enumC4478e12.a() : null, l7, bool2, str5, null);
            searchEventsPayload.setStudySessionId(str6);
            SearchEventsEventLog searchEventsEventLog = new SearchEventsEventLog(searchEventsPayload);
            searchEventsEventLog.setAction(action);
            searchEventsEventLog.getPayload().setUserId(l8);
            searchEventsEventLog.getPayload().setTextbookIsbn(str7);
            searchEventsEventLog.getPayload().setExerciseId(str8);
            return searchEventsEventLog;
        }

        public static SearchEventsEventLog b(String action, SearchData searchData) {
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(searchData, "searchData");
            String currentSearchSessionId = searchData.getCurrentSearchSessionId();
            String query = searchData.getQuery();
            Long depth = searchData.getDepth();
            Long targetObjectId = searchData.getTargetObjectId();
            EnumC4478e1 targetObjectType = searchData.getTargetObjectType();
            String strA = targetObjectType != null ? targetObjectType.a() : null;
            Long targetSessionId = searchData.getTargetSessionId();
            Boolean boolB = searchData.b();
            String selectedFilter = searchData.getSelectedFilter();
            EnumC4472c1 emptyStateView = searchData.getEmptyStateView();
            SearchEventsEventLog searchEventsEventLog = new SearchEventsEventLog(new SearchEventsPayload(currentSearchSessionId, query, depth, targetObjectId, strA, targetSessionId, boolB, selectedFilter, emptyStateView != null ? emptyStateView.a() : null));
            searchEventsEventLog.setAction(action);
            SearchEventsPayload payload = searchEventsEventLog.getPayload();
            SearchType currentTab = searchData.getCurrentTab();
            payload.setCurrentTab(currentTab != null ? currentTab.name() : null);
            searchEventsEventLog.getPayload().setUserId(searchData.getUserID());
            searchEventsEventLog.getPayload().setSetId(searchData.getSetId());
            searchEventsEventLog.getPayload().setUserCreatorId(searchData.getSetCreatorId());
            searchEventsEventLog.getPayload().setOrderedShelfList(searchData.getOrderedShelfList());
            SearchEventsPayload payload2 = searchEventsEventLog.getPayload();
            SearchMisspellingsData misspellingsData = searchData.getMisspellingsData();
            payload2.setOriginalQuery(misspellingsData != null ? misspellingsData.getOriginalQuery() : null);
            SearchEventsPayload payload3 = searchEventsEventLog.getPayload();
            SearchMisspellingsData misspellingsData2 = searchData.getMisspellingsData();
            payload3.setCorrectedQuery(misspellingsData2 != null ? misspellingsData2.getCorrectedQuery() : null);
            return searchEventsEventLog;
        }

        private Companion() {
        }
    }

    public SearchEventsEventLog(@NotNull SearchEventsPayload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
        setTable(EnumC4503n.SEARCH_EVENTS);
    }

    @Override // com.quizlet.eventlogger.model.EventLog
    public final void a(UUID appSessionId, UUID androidDeviceId, Boolean bool, CurrentUserEvent currentUserEvent) {
        Intrinsics.checkNotNullParameter(appSessionId, "appSessionId");
        Intrinsics.checkNotNullParameter(androidDeviceId, "androidDeviceId");
        this.payload.setAppSessionId(appSessionId.toString());
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof SearchEventsEventLog) && Intrinsics.b(this.payload, ((SearchEventsEventLog) obj).payload);
    }

    @JsonProperty("payload")
    @NotNull
    public final SearchEventsPayload getPayload() {
        return this.payload;
    }

    public final int hashCode() {
        return this.payload.hashCode();
    }

    public final String toString() {
        return "SearchEventsEventLog(payload=" + this.payload + ")";
    }
}
