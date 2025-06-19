package com.quizlet.eventlogger.features.search;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import com.quizlet.generated.enums.EnumC4466a1;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SearchMisspellingsData {

    @NotNull
    private final String correctedQuery;
    private final EnumC4466a1 misspellingsTypeEventAction;

    @NotNull
    private final String originalQuery;

    public SearchMisspellingsData(@NotNull String originalQuery, @NotNull String correctedQuery, EnumC4466a1 enumC4466a1) {
        Intrinsics.checkNotNullParameter(originalQuery, "originalQuery");
        Intrinsics.checkNotNullParameter(correctedQuery, "correctedQuery");
        this.originalQuery = originalQuery;
        this.correctedQuery = correctedQuery;
        this.misspellingsTypeEventAction = enumC4466a1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SearchMisspellingsData)) {
            return false;
        }
        SearchMisspellingsData searchMisspellingsData = (SearchMisspellingsData) obj;
        return Intrinsics.b(this.originalQuery, searchMisspellingsData.originalQuery) && Intrinsics.b(this.correctedQuery, searchMisspellingsData.correctedQuery) && this.misspellingsTypeEventAction == searchMisspellingsData.misspellingsTypeEventAction;
    }

    @NotNull
    public final String getCorrectedQuery() {
        return this.correctedQuery;
    }

    public final EnumC4466a1 getMisspellingsTypeEventAction() {
        return this.misspellingsTypeEventAction;
    }

    @NotNull
    public final String getOriginalQuery() {
        return this.originalQuery;
    }

    public final int hashCode() {
        int iE = d0.e(this.originalQuery.hashCode() * 31, 31, this.correctedQuery);
        EnumC4466a1 enumC4466a1 = this.misspellingsTypeEventAction;
        return iE + (enumC4466a1 == null ? 0 : enumC4466a1.hashCode());
    }

    public final String toString() {
        String str = this.originalQuery;
        String str2 = this.correctedQuery;
        EnumC4466a1 enumC4466a1 = this.misspellingsTypeEventAction;
        StringBuilder sbH = AbstractC0147y.h("SearchMisspellingsData(originalQuery=", str, ", correctedQuery=", str2, ", misspellingsTypeEventAction=");
        sbH.append(enumC4466a1);
        sbH.append(")");
        return sbH.toString();
    }

    public /* synthetic */ SearchMisspellingsData(String str, String str2, EnumC4466a1 enumC4466a1, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, (i & 4) != 0 ? null : enumC4466a1);
    }
}
