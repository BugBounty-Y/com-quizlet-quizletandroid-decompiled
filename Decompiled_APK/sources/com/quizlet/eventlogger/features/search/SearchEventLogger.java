package com.quizlet.eventlogger.features.search;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.search.SearchEventsEventLog;
import com.quizlet.eventlogger.features.search.SearchImpressionsEventLog;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.EnumC4466a1;
import com.quizlet.generated.enums.EnumC4478e1;
import com.quizlet.generated.enums.K0;
import com.quizlet.generated.enums.W;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public interface SearchEventLogger {

    @Metadata
    public static final class DefaultImpls {
    }

    @Metadata
    public static final class Impl implements SearchEventLogger {

        @NotNull
        private static final String SCREEN_NAME = "search";

        @NotNull
        private final EventLogger eventLogger;

        @NotNull
        private SearchData searchData;

        @Metadata
        public static final class Companion {
            public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            private Companion() {
            }
        }

        @Metadata
        public /* synthetic */ class WhenMappings {
            public static final /* synthetic */ int[] a;

            static {
                int[] iArr = new int[SearchType.values().length];
                try {
                    iArr[SearchType.b.ordinal()] = 1;
                } catch (NoSuchFieldError unused) {
                }
                try {
                    iArr[SearchType.c.ordinal()] = 2;
                } catch (NoSuchFieldError unused2) {
                }
                try {
                    iArr[SearchType.d.ordinal()] = 3;
                } catch (NoSuchFieldError unused3) {
                }
                try {
                    iArr[SearchType.e.ordinal()] = 4;
                } catch (NoSuchFieldError unused4) {
                }
                try {
                    iArr[SearchType.f.ordinal()] = 5;
                } catch (NoSuchFieldError unused5) {
                }
                try {
                    iArr[SearchType.a.ordinal()] = 6;
                } catch (NoSuchFieldError unused6) {
                }
                a = iArr;
            }
        }

        static {
            new Companion(null);
        }

        public Impl(@NotNull EventLogger eventLogger) {
            Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
            this.eventLogger = eventLogger;
            this.searchData = new SearchData(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 32767, null);
        }

        public static EnumC4478e1 I(SearchType searchType) {
            switch (WhenMappings.a[searchType.ordinal()]) {
                case 1:
                    return EnumC4478e1.SET;
                case 2:
                    return EnumC4478e1.CLAZZ;
                case 3:
                    return EnumC4478e1.USER;
                case 4:
                    return EnumC4478e1.QUESTION;
                case 5:
                    return EnumC4478e1.TEXTBOOK;
                case 6:
                    return null;
                default:
                    throw new NoWhenBranchMatchedException();
            }
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void A(int i, long j) {
            H(j, EnumC4478e1.USER, i);
            F(EnumC4466a1.HIT_USER_RESULT);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void B(String originalQuery, String correctedQuery, EnumC4466a1 action) {
            Intrinsics.checkNotNullParameter(originalQuery, "originalQuery");
            Intrinsics.checkNotNullParameter(correctedQuery, "correctedQuery");
            Intrinsics.checkNotNullParameter(action, "action");
            this.searchData = SearchData.a(this.searchData, null, null, null, null, null, null, null, null, null, null, new SearchMisspellingsData(originalQuery, correctedQuery, action), 16383);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void C(int i, long j) {
            H(j, EnumC4478e1.QUESTION, i);
            F(EnumC4466a1.HIT_EXPLANATION_QUESTION_RESULT);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void D() {
            SearchEventsEventLog.Action action = SearchEventsEventLog.Action.a;
            SearchEventsEventLog.Companion companion = SearchEventsEventLog.b;
            String eventString = action.getEventString();
            SearchData searchData = this.searchData;
            companion.getClass();
            this.eventLogger.l(SearchEventsEventLog.Companion.b(eventString, searchData));
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void E(long j, int i, Boolean bool) {
            this.searchData = SearchData.a(this.searchData, null, null, null, null, bool, null, null, null, null, null, null, 32703);
            H(j, EnumC4478e1.SET, i);
            F(EnumC4466a1.HIT_SET_RESULT);
        }

        public final void F(EnumC4466a1 enumC4466a1) {
            SearchEventsEventLog.Companion companion = SearchEventsEventLog.b;
            String strA = enumC4466a1.a();
            SearchData searchData = this.searchData;
            companion.getClass();
            this.eventLogger.l(SearchEventsEventLog.Companion.b(strA, searchData));
        }

        public final void G(EnumC4466a1 enumC4466a1, String str) {
            this.searchData = SearchData.a(this.searchData, null, null, null, null, null, str, null, null, null, null, null, 32639);
            F(enumC4466a1);
        }

        public final void H(long j, EnumC4478e1 enumC4478e1, long j2) {
            this.searchData = SearchData.a(this.searchData, null, Long.valueOf(j), enumC4478e1, Long.valueOf(j2), null, null, null, null, null, null, null, 32723);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void a(String str) {
            G(EnumC4466a1.CONTENT_TYPE_FILTER, str);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void b(long j, long j2) {
            H(j, EnumC4478e1.TERM, 0L);
            this.searchData = SearchData.a(this.searchData, null, null, null, null, null, null, null, null, Long.valueOf(j2), null, null, 30719);
            F(EnumC4466a1.CLICK_CLOSE_TERM_STUDY_SET_PREVIEW);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void c() {
            this.eventLogger.r(SCREEN_NAME, SearchEventsEventLog.Action.c.getEventString(), W.SUBMIT.a(), true);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void d(String originalQuery, String correctedQuery, EnumC4466a1 action) {
            Intrinsics.checkNotNullParameter(originalQuery, "originalQuery");
            Intrinsics.checkNotNullParameter(correctedQuery, "correctedQuery");
            Intrinsics.checkNotNullParameter(action, "action");
            this.searchData = SearchData.a(this.searchData, null, null, null, null, null, null, null, null, null, null, new SearchMisspellingsData(originalQuery, correctedQuery, null, 4, null), 16383);
            F(action);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void e() {
            F(EnumC4466a1.CLICK_SEARCH_TAB);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void f(long j, long j2) {
            H(j, EnumC4478e1.TERM, 0L);
            this.searchData = SearchData.a(this.searchData, null, null, null, null, null, null, null, null, Long.valueOf(j2), null, null, 30719);
            F(EnumC4466a1.CLICK_TERM_STUDY_SET_PREVIEW_STUDY_BUTTON);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void g() {
            if (this.searchData.getDepth() == null || this.searchData.getTargetObjectId() == null) {
                return;
            }
            F(EnumC4466a1.HIT_SHARE);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void h(int i, long j) {
            H(j, EnumC4478e1.TEXTBOOK, i);
            F(EnumC4466a1.HIT_TEXTBOOK_RESULT);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void i(String textbookIsbn, String exerciseId) {
            Intrinsics.checkNotNullParameter(textbookIsbn, "textbookIsbn");
            Intrinsics.checkNotNullParameter(exerciseId, "exerciseId");
            EnumC4478e1 targetObjectType = this.searchData.getTargetObjectType();
            if (this.searchData.getDepth() == null || this.searchData.getTargetObjectId() == null || targetObjectType == null || targetObjectType != EnumC4478e1.TEXTBOOK) {
                return;
            }
            this.eventLogger.l(SearchEventsEventLog.Companion.a(SearchEventsEventLog.b, this.searchData.getSearchSessionIdData().b(targetObjectType), EnumC4466a1.HIT_EXERCISE.a(), this.searchData.getQuery(), this.searchData.getDepth(), this.searchData.getTargetObjectId(), this.searchData.getTargetObjectType(), null, this.searchData.b(), null, null, this.searchData.getUserID(), textbookIsbn, exerciseId, 1856));
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void j(int i, long j) {
            H(j, EnumC4478e1.CLAZZ, i);
            F(EnumC4466a1.HIT_CLASS_RESULT);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void k() {
            if (this.searchData.getDepth() != null) {
                F(EnumC4466a1.HIT_RETURN);
            }
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void l(String studySessionId) {
            Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
            EnumC4478e1 targetObjectType = this.searchData.getTargetObjectType();
            if (this.searchData.getDepth() == null || this.searchData.getTargetObjectId() == null || targetObjectType == null) {
                return;
            }
            this.eventLogger.l(SearchEventsEventLog.Companion.a(SearchEventsEventLog.b, this.searchData.getCurrentSearchSessionId(), EnumC4466a1.EMBED_FLASHCARDS_ENGAGED.a(), this.searchData.getQuery(), this.searchData.getDepth(), this.searchData.getTargetObjectId(), this.searchData.getTargetObjectType(), null, this.searchData.b(), this.searchData.getSelectedFilter(), studySessionId, null, null, null, 14912));
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void m(String str) {
            G(EnumC4466a1.CREATED_BY_FILTER, str);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void n(A1 studyModeType, String studySessionId) {
            Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
            Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
            EnumC4478e1 targetObjectType = this.searchData.getTargetObjectType();
            if (this.searchData.getDepth() == null || this.searchData.getTargetObjectId() == null || targetObjectType == null) {
                return;
            }
            this.eventLogger.l(SearchEventsEventLog.Companion.a(SearchEventsEventLog.b, this.searchData.getCurrentSearchSessionId(), EnumC4466a1.HIT_STUDY.a(), this.searchData.getQuery(), this.searchData.getDepth(), this.searchData.getTargetObjectId(), this.searchData.getTargetObjectType(), Long.valueOf(studyModeType.a()), this.searchData.b(), this.searchData.getSelectedFilter(), studySessionId, null, null, null, 14848));
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void o(int i, long j, int i2, SearchType pageType, K0 purchasableType) {
            Intrinsics.checkNotNullParameter(pageType, "pageType");
            Intrinsics.checkNotNullParameter(purchasableType, "purchasableType");
            SearchImpressionsEventLog.Companion companion = SearchImpressionsEventLog.b;
            SearchData searchData = this.searchData;
            Date clientTimestamp = new Date();
            companion.getClass();
            Intrinsics.checkNotNullParameter(searchData, "searchData");
            Intrinsics.checkNotNullParameter(purchasableType, "purchasableType");
            Intrinsics.checkNotNullParameter(clientTimestamp, "clientTimestamp");
            String currentSearchSessionId = searchData.getCurrentSearchSessionId();
            int iA = purchasableType.a();
            String query = searchData.getQuery();
            SearchType currentTab = searchData.getCurrentTab();
            SearchImpressionsEventLog searchImpressionsEventLog = new SearchImpressionsEventLog(new SearchImpressionsEventLog.SearchImpressionsPayload(currentSearchSessionId, j, null, 1, i2, Integer.valueOf(i), iA, clientTimestamp, null, query, null, currentTab != null ? currentTab.name() : null, 0, 5380, null));
            searchImpressionsEventLog.setAction("user_action_search");
            String versionName = this.eventLogger.getVersionName();
            Intrinsics.checkNotNullExpressionValue(versionName, "getVersionName(...)");
            searchImpressionsEventLog.setVersionName(versionName);
            this.eventLogger.v(searchImpressionsEventLog);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void p(long j, long j2, int i) {
            H(j, EnumC4478e1.TERM, i);
            this.searchData = SearchData.a(this.searchData, null, null, null, null, null, null, null, null, Long.valueOf(j2), null, null, 30719);
            F(EnumC4466a1.CLICK_TERM_STUDY_SET_PREVIEW);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void q(List orderedShelfList) {
            Intrinsics.checkNotNullParameter(orderedShelfList, "orderedShelfList");
            SearchData searchData = this.searchData;
            ArrayList arrayList = new ArrayList(C.q(orderedShelfList, 10));
            Iterator it2 = orderedShelfList.iterator();
            while (it2.hasNext()) {
                arrayList.add(((EnumC4478e1) it2.next()).a());
            }
            this.searchData = SearchData.a(searchData, null, null, null, null, null, null, null, null, null, arrayList, null, 24575);
            F(EnumC4466a1.BLENDED_RESULTS_ORDERED_SHELF_LIST);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void r(SearchType type, String sessionId) {
            SearchSessionData searchSessionDataA;
            Intrinsics.checkNotNullParameter(type, "type");
            Intrinsics.checkNotNullParameter(sessionId, "sessionId");
            SearchSessionData searchSessionIdData = this.searchData.getSearchSessionIdData();
            switch (WhenMappings.a[type.ordinal()]) {
                case 1:
                    searchSessionDataA = SearchSessionData.a(searchSessionIdData, sessionId, null, null, null, null, null, 62);
                    break;
                case 2:
                    searchSessionDataA = SearchSessionData.a(searchSessionIdData, null, sessionId, null, null, null, null, 61);
                    break;
                case 3:
                    searchSessionDataA = SearchSessionData.a(searchSessionIdData, null, null, sessionId, null, null, null, 59);
                    break;
                case 4:
                    searchSessionDataA = SearchSessionData.a(searchSessionIdData, null, null, null, sessionId, null, null, 55);
                    break;
                case 5:
                    searchSessionDataA = SearchSessionData.a(searchSessionIdData, null, null, null, null, sessionId, null, 47);
                    break;
                case 6:
                    searchSessionDataA = SearchSessionData.a(searchSessionIdData, null, null, null, null, null, sessionId, 31);
                    break;
                default:
                    throw new NoWhenBranchMatchedException();
            }
            this.searchData = SearchData.a(this.searchData, searchSessionDataA, null, null, null, null, null, null, null, null, null, null, 32766);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void s() {
            EnumC4466a1 misspellingsTypeEventAction;
            SearchMisspellingsData misspellingsData = this.searchData.getMisspellingsData();
            if (misspellingsData == null || (misspellingsTypeEventAction = misspellingsData.getMisspellingsTypeEventAction()) == null) {
                return;
            }
            F(misspellingsTypeEventAction);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public void setCurrentSearchTab(@NotNull SearchType tab) {
            Intrinsics.checkNotNullParameter(tab, "tab");
            this.searchData = SearchData.a(this.searchData, null, null, null, null, null, null, tab, null, null, null, null, 32255);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public void setQueryAndResetData(@NotNull String query) {
            Intrinsics.checkNotNullParameter(query, "query");
            this.searchData = new SearchData(null, query, null, null, null, null, null, null, null, SearchType.a, this.searchData.getUserID(), null, null, null, null, 31229, null);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public void setUserId(Long l) {
            this.searchData = SearchData.a(this.searchData, null, null, null, null, null, null, null, l, null, null, null, 31743);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void t(String str) {
            G(EnumC4466a1.NUMBER_OF_TERMS_FILTER, str);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void u(SearchType currentPage, String sessionId) {
            Intrinsics.checkNotNullParameter(currentPage, "currentPage");
            Intrinsics.checkNotNullParameter(sessionId, "sessionId");
            if (sessionId.length() > 0) {
                r(currentPage, sessionId);
                this.searchData = SearchData.a(this.searchData, null, null, I(currentPage), null, null, null, null, null, null, null, null, 32759);
                F(EnumC4466a1.RESULTS_VIEWED);
            }
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void v(long j, long j2, int i) {
            H(j, EnumC4478e1.TERM, i);
            this.searchData = SearchData.a(this.searchData, null, null, null, null, null, null, null, null, Long.valueOf(j2), null, null, 30719);
            F(EnumC4466a1.HIT_TERM_RESULT);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void w(long j, long j2) {
            H(j, EnumC4478e1.TERM, 0L);
            this.searchData = SearchData.a(this.searchData, null, null, null, null, null, null, null, null, Long.valueOf(j2), null, null, 30719);
            F(EnumC4466a1.TERM_SCREEN_FAILED_LOAD);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void x(int i, long j) {
            H(j, EnumC4478e1.SET, i);
            SearchEventsEventLog.Action action = SearchEventsEventLog.Action.b;
            SearchEventsEventLog.Companion companion = SearchEventsEventLog.b;
            String eventString = action.getEventString();
            SearchData searchData = this.searchData;
            companion.getClass();
            this.eventLogger.l(SearchEventsEventLog.Companion.b(eventString, searchData));
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void y() {
            this.eventLogger.r(SCREEN_NAME, SearchEventsEventLog.Action.d.getEventString(), W.SUBMIT.a(), true);
        }

        @Override // com.quizlet.eventlogger.features.search.SearchEventLogger
        public final void z(SearchType currentPage, String sessionId) {
            Intrinsics.checkNotNullParameter(currentPage, "currentPage");
            Intrinsics.checkNotNullParameter(sessionId, "sessionId");
            if (sessionId.length() > 0) {
                r(currentPage, sessionId);
                this.searchData = SearchData.a(this.searchData, null, null, I(currentPage), null, null, null, null, null, null, null, null, 32759);
                F(EnumC4466a1.SHOW_NO_RESULTS_RETURNED);
            }
        }
    }

    void A(int i, long j);

    void B(String str, String str2, EnumC4466a1 enumC4466a1);

    void C(int i, long j);

    void D();

    void E(long j, int i, Boolean bool);

    void a(String str);

    void b(long j, long j2);

    void c();

    void d(String str, String str2, EnumC4466a1 enumC4466a1);

    void e();

    void f(long j, long j2);

    void g();

    void h(int i, long j);

    void i(String str, String str2);

    void j(int i, long j);

    void k();

    void l(String str);

    void m(String str);

    void n(A1 a1, String str);

    void o(int i, long j, int i2, SearchType searchType, K0 k0);

    void p(long j, long j2, int i);

    void q(List list);

    void r(SearchType searchType, String str);

    void s();

    void setCurrentSearchTab(@NotNull SearchType searchType);

    void setQueryAndResetData(@NotNull String str);

    void setUserId(Long l);

    void t(String str);

    void u(SearchType searchType, String str);

    void v(long j, long j2, int i);

    void w(long j, long j2);

    void x(int i, long j);

    void y();

    void z(SearchType searchType, String str);
}
