package com.quizlet.eventlogger.features.folder;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.eventlogger.features.search.SearchEventsEventLog;
import com.quizlet.eventlogger.features.search.SearchImpressionsEventLog;
import com.quizlet.eventlogger.model.NavigationEventLog;
import com.quizlet.generated.enums.EnumC4466a1;
import com.quizlet.generated.enums.y1;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class FolderLogger {

    @NotNull
    private final EventLogger eventLogger;

    @NotNull
    private String screenName;

    @Metadata
    public static final class Actions {
        static {
            new Actions();
        }

        private Actions() {
        }
    }

    public FolderLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
        this.screenName = "";
    }

    public final void A() {
        this.eventLogger.r(this.screenName, "save_item_create_new_folder_clicked", "info", true);
    }

    public final void B(String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "save_to_folder_clicked", "info");
        navigationEventLogB.getPayload().c(Integer.valueOf(studyMaterialType.b()), studyMaterialId);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void C(String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "save_to_folder_confirm_clicked", "info");
        navigationEventLogB.getPayload().c(Integer.valueOf(studyMaterialType.b()), studyMaterialId);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void D(long j, String studyMaterialId, y1 studyMaterialType, boolean z) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "save_to_folder_existing_folder_clicked", "info");
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogB.getPayload().c(Integer.valueOf(studyMaterialType.b()), studyMaterialId);
        NavigationEventLog.Payload.AdditionalInfo additionalInfo = navigationEventLogB.getPayload().getAdditionalInfo();
        if (additionalInfo != null) {
            additionalInfo.setSelected(Boolean.valueOf(z));
        }
        this.eventLogger.l(navigationEventLogB);
    }

    public final void E(long j, String studyMaterialId, y1 studyMaterialType, boolean z) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "save_to_folder_existing_folder_expansion_clicked", "info");
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogB.getPayload().c(Integer.valueOf(studyMaterialType.b()), studyMaterialId);
        NavigationEventLog.Payload.AdditionalInfo additionalInfo = navigationEventLogB.getPayload().getAdditionalInfo();
        if (additionalInfo != null) {
            additionalInfo.setExpanded(Boolean.valueOf(z));
        }
        this.eventLogger.l(navigationEventLogB);
    }

    public final void F(long j, y1 studyMaterialType, String tagName, String studyMaterialId, boolean z) {
        Intrinsics.checkNotNullParameter(tagName, "tagName");
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "save_to_folder_existing_tag_clicked", "info");
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogB.getPayload().setTagName(tagName);
        navigationEventLogB.getPayload().c(Integer.valueOf(studyMaterialType.b()), studyMaterialId);
        NavigationEventLog.Payload.AdditionalInfo additionalInfo = navigationEventLogB.getPayload().getAdditionalInfo();
        if (additionalInfo != null) {
            additionalInfo.setSelected(Boolean.valueOf(z));
        }
        this.eventLogger.l(navigationEventLogB);
    }

    public final void G(String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "save_to_folder_undo_clicked", "info");
        navigationEventLogB.getPayload().c(Integer.valueOf(studyMaterialType.b()), studyMaterialId);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void H(long j, long j2, String schoolQuery, String searchSessionId) {
        Intrinsics.checkNotNullParameter(schoolQuery, "schoolQuery");
        Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
        SearchImpressionsEventLog.Companion companion = SearchImpressionsEventLog.b;
        String strValueOf = String.valueOf(j);
        companion.getClass();
        this.eventLogger.l(SearchImpressionsEventLog.Companion.a(searchSessionId, (int) j2, schoolQuery, strValueOf, 5));
    }

    public final void I(long j) {
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, false, this.screenName, "add_custom_tag_screen_seen", "info");
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        this.eventLogger.l(navigationEventLogB);
    }

    public final void a(long j, List addedTags) {
        Intrinsics.checkNotNullParameter(addedTags, "addedTags");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "add_tags_confirm_clicked", "info");
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogB.getPayload().setTagsAdded(addedTags);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void b(String str, y1 y1Var, long j, List tagsAdded) {
        Intrinsics.checkNotNullParameter(tagsAdded, "tagsAdded");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "folder_item_tag_changes_saved", "info");
        navigationEventLogB.getPayload().c(y1Var != null ? Integer.valueOf(y1Var.b()) : null, str);
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogB.getPayload().setTagsAdded(tagsAdded);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void c(String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, false, this.screenName, "folder_item_change_tags_viewed", "info");
        navigationEventLogB.getPayload().c(Integer.valueOf(studyMaterialType.b()), studyMaterialId);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void d(long j, String tagName) {
        Intrinsics.checkNotNullParameter(tagName, "tagName");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "add_custom_tag_confirm_clicked", "info");
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogB.getPayload().setTagName(tagName);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void e(long j, String tagName) {
        Intrinsics.checkNotNullParameter(tagName, "tagName");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "add_custom_tag_recommended_tag_clicked", "info");
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogB.getPayload().setTagName(tagName);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void f(long j, long j2, String courseQuery, String searchSessionId) {
        Intrinsics.checkNotNullParameter(courseQuery, "courseQuery");
        Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
        SearchImpressionsEventLog.Companion companion = SearchImpressionsEventLog.b;
        String strValueOf = String.valueOf(j);
        companion.getClass();
        this.eventLogger.l(SearchImpressionsEventLog.Companion.a(searchSessionId, (int) j2, courseQuery, strValueOf, 13));
    }

    public final void g() {
        this.eventLogger.r(this.screenName, "create_folder_create_clicked", "info", true);
    }

    public final void h(Long l, boolean z) {
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "create_folder_for_course_toggled", "info");
        navigationEventLogB.setToggled(z);
        navigationEventLogB.getPayload().setFolderId(l);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void i() {
        this.eventLogger.r(this.screenName, "create_folder_screen_seen", "info", false);
    }

    public final void j(Long l) {
        EventLoggerExt.a(this.eventLogger, "folder_title_updated", new a(0, l));
    }

    public final void k(long j) {
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "add_custom_tag_screen_dismissed", "info");
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        this.eventLogger.l(navigationEventLogB);
    }

    public final void l() {
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, false, this.screenName, "folder_tag_limit_reached", "info");
        navigationEventLogB.getPayload().setFolderId(0L);
        navigationEventLogB.getPayload().setLimit(30);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void m(String tagName) {
        Intrinsics.checkNotNullParameter(tagName, "tagName");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, false, this.screenName, "add_custom_tag_warning_too_long", "info");
        navigationEventLogB.getPayload().setFolderId(0L);
        navigationEventLogB.getPayload().setTagName(tagName);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void n() {
        this.eventLogger.r(this.screenName, "edgy_data_course_screen_seen", "info", false);
    }

    public final void o() {
        this.eventLogger.r(this.screenName, "edgy_data_school_screen_seen", "info", false);
    }

    public final void p(Long l) {
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "edit_folder_done_clicked", "info");
        navigationEventLogB.getPayload().setFolderId(l);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void q(Long l) {
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, false, this.screenName, "edit_folder_screen_seen", "info");
        navigationEventLogB.getPayload().setFolderId(l);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void r(long j, String str) {
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "edit_tag_confirm_clicked", "info");
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogB.getPayload().setTagName(str);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void s(long j, String str) {
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "edit_tag_screen_dismissed", "info");
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogB.getPayload().setTagName(str);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void setScreenName(@NotNull String screenName) {
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        this.screenName = screenName;
    }

    public final void t(long j, String str) {
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "edit_tag_remove_clicked", "info");
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogB.getPayload().setTagName(str);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void u(long j, String tagName) {
        Intrinsics.checkNotNullParameter(tagName, "tagName");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, false, this.screenName, "edit_tag_screen_seen", "info");
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogB.getPayload().setTagName(tagName);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void v(long j, y1 y1Var, String str, String tagName, boolean z) {
        Intrinsics.checkNotNullParameter(tagName, "tagName");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "folder_item_tag_clicked", "info");
        navigationEventLogB.getPayload().c(y1Var != null ? Integer.valueOf(y1Var.b()) : null, str);
        navigationEventLogB.getPayload().setFolderId(Long.valueOf(j));
        navigationEventLogB.getPayload().setTagName(tagName);
        NavigationEventLog.Payload.AdditionalInfo additionalInfo = navigationEventLogB.getPayload().getAdditionalInfo();
        if (additionalInfo != null) {
            additionalInfo.setSelected(Boolean.valueOf(z));
        }
        this.eventLogger.l(navigationEventLogB);
    }

    public final void w(long j, Long l, String courseQuery, String searchSessionId) {
        Intrinsics.checkNotNullParameter(courseQuery, "courseQuery");
        Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
        this.eventLogger.l(SearchEventsEventLog.Companion.a(SearchEventsEventLog.b, searchSessionId, EnumC4466a1.HIT_SELECT_COURSE.a(), courseQuery, l, Long.valueOf(j), null, null, null, null, null, null, null, null, 16352));
    }

    public final void x(long j, Long l, String schoolQuery, String searchSessionId) {
        Intrinsics.checkNotNullParameter(schoolQuery, "schoolQuery");
        Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
        this.eventLogger.l(SearchEventsEventLog.Companion.a(SearchEventsEventLog.b, searchSessionId, EnumC4466a1.HIT_SELECT_SCHOOL.a(), schoolQuery, l, Long.valueOf(j), null, null, null, null, null, null, null, null, 16352));
    }

    public final void y(String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, true, this.screenName, "save_item_bottom_sheet_dismissed", "info");
        navigationEventLogB.getPayload().c(Integer.valueOf(studyMaterialType.b()), studyMaterialId);
        this.eventLogger.l(navigationEventLogB);
    }

    public final void z(String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        NavigationEventLog navigationEventLogB = NavigationEventLog.Companion.b(NavigationEventLog.b, false, this.screenName, "save_item_bottom_sheet_seen", "info");
        navigationEventLogB.getPayload().c(Integer.valueOf(studyMaterialType.b()), studyMaterialId);
        this.eventLogger.l(navigationEventLogB);
    }
}
