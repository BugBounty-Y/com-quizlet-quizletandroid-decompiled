package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class LanguageSuggestionRequest {
    private final Integer limit;
    private final Long localSetId;

    @NotNull
    private final String strings;
    private final Long userId;

    public LanguageSuggestionRequest(@JsonProperty("strings") @NotNull String strings, @JsonProperty("localSetId") Long l, @JsonProperty("limit") Integer num, @JsonProperty("userId") Long l2) {
        Intrinsics.checkNotNullParameter(strings, "strings");
        this.strings = strings;
        this.localSetId = l;
        this.limit = num;
        this.userId = l2;
    }

    public static /* synthetic */ LanguageSuggestionRequest copy$default(LanguageSuggestionRequest languageSuggestionRequest, String str, Long l, Integer num, Long l2, int i, Object obj) {
        if ((i & 1) != 0) {
            str = languageSuggestionRequest.strings;
        }
        if ((i & 2) != 0) {
            l = languageSuggestionRequest.localSetId;
        }
        if ((i & 4) != 0) {
            num = languageSuggestionRequest.limit;
        }
        if ((i & 8) != 0) {
            l2 = languageSuggestionRequest.userId;
        }
        return languageSuggestionRequest.copy(str, l, num, l2);
    }

    @NotNull
    public final String component1() {
        return this.strings;
    }

    public final Long component2() {
        return this.localSetId;
    }

    public final Integer component3() {
        return this.limit;
    }

    public final Long component4() {
        return this.userId;
    }

    @NotNull
    public final LanguageSuggestionRequest copy(@JsonProperty("strings") @NotNull String strings, @JsonProperty("localSetId") Long l, @JsonProperty("limit") Integer num, @JsonProperty("userId") Long l2) {
        Intrinsics.checkNotNullParameter(strings, "strings");
        return new LanguageSuggestionRequest(strings, l, num, l2);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LanguageSuggestionRequest)) {
            return false;
        }
        LanguageSuggestionRequest languageSuggestionRequest = (LanguageSuggestionRequest) obj;
        return Intrinsics.b(this.strings, languageSuggestionRequest.strings) && Intrinsics.b(this.localSetId, languageSuggestionRequest.localSetId) && Intrinsics.b(this.limit, languageSuggestionRequest.limit) && Intrinsics.b(this.userId, languageSuggestionRequest.userId);
    }

    public final Integer getLimit() {
        return this.limit;
    }

    public final Long getLocalSetId() {
        return this.localSetId;
    }

    @NotNull
    public final String getStrings() {
        return this.strings;
    }

    public final Long getUserId() {
        return this.userId;
    }

    public int hashCode() {
        int iHashCode = this.strings.hashCode() * 31;
        Long l = this.localSetId;
        int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
        Integer num = this.limit;
        int iHashCode3 = (iHashCode2 + (num == null ? 0 : num.hashCode())) * 31;
        Long l2 = this.userId;
        return iHashCode3 + (l2 != null ? l2.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        return "LanguageSuggestionRequest(strings=" + this.strings + ", localSetId=" + this.localSetId + ", limit=" + this.limit + ", userId=" + this.userId + ")";
    }
}
