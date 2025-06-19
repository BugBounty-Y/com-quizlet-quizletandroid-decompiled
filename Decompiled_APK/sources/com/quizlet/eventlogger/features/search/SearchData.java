package com.quizlet.eventlogger.features.search;

import androidx.compose.animation.d0;
import com.google.android.gms.ads.g;
import com.quizlet.generated.enums.EnumC4472c1;
import com.quizlet.generated.enums.EnumC4478e1;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SearchData {
    private final SearchType currentTab;
    private final Long depth;
    private final EnumC4472c1 emptyStateView;
    private final Boolean isVerifiedCreatorContent;
    private final SearchMisspellingsData misspellingsData;
    private final List<String> orderedShelfList;

    @NotNull
    private final String query;

    @NotNull
    private final SearchSessionData searchSessionIdData;
    private final String selectedFilter;
    private final Long setCreatorId;
    private final Long setId;
    private final Long targetObjectId;
    private final EnumC4478e1 targetObjectType;
    private final Long targetSessionId;
    private final Long userID;

    @Metadata
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] a;

        static {
            int[] iArr = new int[SearchType.values().length];
            try {
                iArr[SearchType.a.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[SearchType.b.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[SearchType.c.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[SearchType.d.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                iArr[SearchType.e.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                iArr[SearchType.f.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
            a = iArr;
        }
    }

    public SearchData() {
        this(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 32767, null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static SearchData a(SearchData searchData, SearchSessionData searchSessionData, Long l, EnumC4478e1 enumC4478e1, Long l2, Boolean bool, String str, SearchType searchType, Long l3, Long l4, ArrayList arrayList, SearchMisspellingsData searchMisspellingsData, int i) {
        SearchSessionData searchSessionIdData = (i & 1) != 0 ? searchData.searchSessionIdData : searchSessionData;
        String query = searchData.query;
        Long l5 = (i & 4) != 0 ? searchData.targetObjectId : l;
        EnumC4478e1 enumC4478e12 = (i & 8) != 0 ? searchData.targetObjectType : enumC4478e1;
        Long l6 = searchData.targetSessionId;
        Long l7 = (i & 32) != 0 ? searchData.depth : l2;
        Boolean bool2 = (i & 64) != 0 ? searchData.isVerifiedCreatorContent : bool;
        String str2 = (i & 128) != 0 ? searchData.selectedFilter : str;
        EnumC4472c1 enumC4472c1 = searchData.emptyStateView;
        SearchType searchType2 = (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? searchData.currentTab : searchType;
        Long l8 = (i & 1024) != 0 ? searchData.userID : l3;
        Long l9 = (i & 2048) != 0 ? searchData.setId : l4;
        Long l10 = searchData.setCreatorId;
        List list = (i & 8192) != 0 ? searchData.orderedShelfList : arrayList;
        SearchMisspellingsData searchMisspellingsData2 = (i & 16384) != 0 ? searchData.misspellingsData : searchMisspellingsData;
        searchData.getClass();
        Intrinsics.checkNotNullParameter(searchSessionIdData, "searchSessionIdData");
        Intrinsics.checkNotNullParameter(query, "query");
        return new SearchData(searchSessionIdData, query, l5, enumC4478e12, l6, l7, bool2, str2, enumC4472c1, searchType2, l8, l9, l10, list, searchMisspellingsData2);
    }

    public final Boolean b() {
        return this.isVerifiedCreatorContent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SearchData)) {
            return false;
        }
        SearchData searchData = (SearchData) obj;
        return Intrinsics.b(this.searchSessionIdData, searchData.searchSessionIdData) && Intrinsics.b(this.query, searchData.query) && Intrinsics.b(this.targetObjectId, searchData.targetObjectId) && this.targetObjectType == searchData.targetObjectType && Intrinsics.b(this.targetSessionId, searchData.targetSessionId) && Intrinsics.b(this.depth, searchData.depth) && Intrinsics.b(this.isVerifiedCreatorContent, searchData.isVerifiedCreatorContent) && Intrinsics.b(this.selectedFilter, searchData.selectedFilter) && this.emptyStateView == searchData.emptyStateView && this.currentTab == searchData.currentTab && Intrinsics.b(this.userID, searchData.userID) && Intrinsics.b(this.setId, searchData.setId) && Intrinsics.b(this.setCreatorId, searchData.setCreatorId) && Intrinsics.b(this.orderedShelfList, searchData.orderedShelfList) && Intrinsics.b(this.misspellingsData, searchData.misspellingsData);
    }

    @NotNull
    public final String getCurrentSearchSessionId() {
        SearchType searchType = this.currentTab;
        switch (searchType == null ? -1 : WhenMappings.a[searchType.ordinal()]) {
            case -1:
                return "";
            case 0:
            default:
                throw new NoWhenBranchMatchedException();
            case 1:
                return this.searchSessionIdData.getAllSearchSessionId();
            case 2:
                return this.searchSessionIdData.getSetSearchSessionId();
            case 3:
                return this.searchSessionIdData.getGroupSearchSessionId();
            case 4:
                return this.searchSessionIdData.getUserSearchSessionId();
            case 5:
                return this.searchSessionIdData.getQuestionSearchSessionId();
            case 6:
                return this.searchSessionIdData.getTextbookSearchSessionId();
        }
    }

    public final SearchType getCurrentTab() {
        return this.currentTab;
    }

    public final Long getDepth() {
        return this.depth;
    }

    public final EnumC4472c1 getEmptyStateView() {
        return this.emptyStateView;
    }

    public final SearchMisspellingsData getMisspellingsData() {
        return this.misspellingsData;
    }

    public final List<String> getOrderedShelfList() {
        return this.orderedShelfList;
    }

    @NotNull
    public final String getQuery() {
        return this.query;
    }

    @NotNull
    public final SearchSessionData getSearchSessionIdData() {
        return this.searchSessionIdData;
    }

    public final String getSelectedFilter() {
        return this.selectedFilter;
    }

    public final Long getSetCreatorId() {
        return this.setCreatorId;
    }

    public final Long getSetId() {
        return this.setId;
    }

    public final Long getTargetObjectId() {
        return this.targetObjectId;
    }

    public final EnumC4478e1 getTargetObjectType() {
        return this.targetObjectType;
    }

    public final Long getTargetSessionId() {
        return this.targetSessionId;
    }

    public final Long getUserID() {
        return this.userID;
    }

    public final int hashCode() {
        int iE = d0.e(this.searchSessionIdData.hashCode() * 31, 31, this.query);
        Long l = this.targetObjectId;
        int iHashCode = (iE + (l == null ? 0 : l.hashCode())) * 31;
        EnumC4478e1 enumC4478e1 = this.targetObjectType;
        int iHashCode2 = (iHashCode + (enumC4478e1 == null ? 0 : enumC4478e1.hashCode())) * 31;
        Long l2 = this.targetSessionId;
        int iHashCode3 = (iHashCode2 + (l2 == null ? 0 : l2.hashCode())) * 31;
        Long l3 = this.depth;
        int iHashCode4 = (iHashCode3 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Boolean bool = this.isVerifiedCreatorContent;
        int iHashCode5 = (iHashCode4 + (bool == null ? 0 : bool.hashCode())) * 31;
        String str = this.selectedFilter;
        int iHashCode6 = (iHashCode5 + (str == null ? 0 : str.hashCode())) * 31;
        EnumC4472c1 enumC4472c1 = this.emptyStateView;
        int iHashCode7 = (iHashCode6 + (enumC4472c1 == null ? 0 : enumC4472c1.hashCode())) * 31;
        SearchType searchType = this.currentTab;
        int iHashCode8 = (iHashCode7 + (searchType == null ? 0 : searchType.hashCode())) * 31;
        Long l4 = this.userID;
        int iHashCode9 = (iHashCode8 + (l4 == null ? 0 : l4.hashCode())) * 31;
        Long l5 = this.setId;
        int iHashCode10 = (iHashCode9 + (l5 == null ? 0 : l5.hashCode())) * 31;
        Long l6 = this.setCreatorId;
        int iHashCode11 = (iHashCode10 + (l6 == null ? 0 : l6.hashCode())) * 31;
        List<String> list = this.orderedShelfList;
        int iHashCode12 = (iHashCode11 + (list == null ? 0 : list.hashCode())) * 31;
        SearchMisspellingsData searchMisspellingsData = this.misspellingsData;
        return iHashCode12 + (searchMisspellingsData != null ? searchMisspellingsData.hashCode() : 0);
    }

    public final String toString() {
        return "SearchData(searchSessionIdData=" + this.searchSessionIdData + ", query=" + this.query + ", targetObjectId=" + this.targetObjectId + ", targetObjectType=" + this.targetObjectType + ", targetSessionId=" + this.targetSessionId + ", depth=" + this.depth + ", isVerifiedCreatorContent=" + this.isVerifiedCreatorContent + ", selectedFilter=" + this.selectedFilter + ", emptyStateView=" + this.emptyStateView + ", currentTab=" + this.currentTab + ", userID=" + this.userID + ", setId=" + this.setId + ", setCreatorId=" + this.setCreatorId + ", orderedShelfList=" + this.orderedShelfList + ", misspellingsData=" + this.misspellingsData + ")";
    }

    public SearchData(@NotNull SearchSessionData searchSessionIdData, @NotNull String query, Long l, EnumC4478e1 enumC4478e1, Long l2, Long l3, Boolean bool, String str, EnumC4472c1 enumC4472c1, SearchType searchType, Long l4, Long l5, Long l6, List<String> list, SearchMisspellingsData searchMisspellingsData) {
        Intrinsics.checkNotNullParameter(searchSessionIdData, "searchSessionIdData");
        Intrinsics.checkNotNullParameter(query, "query");
        this.searchSessionIdData = searchSessionIdData;
        this.query = query;
        this.targetObjectId = l;
        this.targetObjectType = enumC4478e1;
        this.targetSessionId = l2;
        this.depth = l3;
        this.isVerifiedCreatorContent = bool;
        this.selectedFilter = str;
        this.emptyStateView = enumC4472c1;
        this.currentTab = searchType;
        this.userID = l4;
        this.setId = l5;
        this.setCreatorId = l6;
        this.orderedShelfList = list;
        this.misspellingsData = searchMisspellingsData;
    }

    public /* synthetic */ SearchData(SearchSessionData searchSessionData, String str, Long l, EnumC4478e1 enumC4478e1, Long l2, Long l3, Boolean bool, String str2, EnumC4472c1 enumC4472c1, SearchType searchType, Long l4, Long l5, Long l6, List list, SearchMisspellingsData searchMisspellingsData, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? new SearchSessionData(null, null, null, null, null, null, 63, null) : searchSessionData, (i & 2) != 0 ? "" : str, (i & 4) != 0 ? null : l, (i & 8) != 0 ? null : enumC4478e1, (i & 16) != 0 ? null : l2, (i & 32) != 0 ? null : l3, (i & 64) != 0 ? null : bool, (i & 128) != 0 ? null : str2, (i & 256) != 0 ? null : enumC4472c1, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : searchType, (i & 1024) != 0 ? null : l4, (i & 2048) != 0 ? null : l5, (i & 4096) != 0 ? null : l6, (i & 8192) != 0 ? null : list, (i & 16384) != 0 ? null : searchMisspellingsData);
    }
}
