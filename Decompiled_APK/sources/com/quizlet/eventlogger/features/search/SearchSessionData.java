package com.quizlet.eventlogger.features.search;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import androidx.compose.ui.node.B;
import com.quizlet.generated.enums.EnumC4478e1;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import timber.log.c;

@Metadata
/* loaded from: classes2.dex */
public final class SearchSessionData {

    @NotNull
    private final String allSearchSessionId;

    @NotNull
    private final String groupSearchSessionId;

    @NotNull
    private final String questionSearchSessionId;

    @NotNull
    private final String setSearchSessionId;

    @NotNull
    private final String textbookSearchSessionId;

    @NotNull
    private final String userSearchSessionId;

    @Metadata
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] a;

        static {
            int[] iArr = new int[EnumC4478e1.values().length];
            try {
                iArr[EnumC4478e1.SET.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[EnumC4478e1.CLAZZ.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[EnumC4478e1.USER.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[EnumC4478e1.QUESTION.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                iArr[EnumC4478e1.TEXTBOOK.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            a = iArr;
        }
    }

    public SearchSessionData() {
        this(null, null, null, null, null, null, 63, null);
    }

    public static SearchSessionData a(SearchSessionData searchSessionData, String str, String str2, String str3, String str4, String str5, String str6, int i) {
        if ((i & 1) != 0) {
            str = searchSessionData.setSearchSessionId;
        }
        String setSearchSessionId = str;
        if ((i & 2) != 0) {
            str2 = searchSessionData.groupSearchSessionId;
        }
        String groupSearchSessionId = str2;
        if ((i & 4) != 0) {
            str3 = searchSessionData.userSearchSessionId;
        }
        String userSearchSessionId = str3;
        if ((i & 8) != 0) {
            str4 = searchSessionData.questionSearchSessionId;
        }
        String questionSearchSessionId = str4;
        if ((i & 16) != 0) {
            str5 = searchSessionData.textbookSearchSessionId;
        }
        String textbookSearchSessionId = str5;
        if ((i & 32) != 0) {
            str6 = searchSessionData.allSearchSessionId;
        }
        String allSearchSessionId = str6;
        searchSessionData.getClass();
        Intrinsics.checkNotNullParameter(setSearchSessionId, "setSearchSessionId");
        Intrinsics.checkNotNullParameter(groupSearchSessionId, "groupSearchSessionId");
        Intrinsics.checkNotNullParameter(userSearchSessionId, "userSearchSessionId");
        Intrinsics.checkNotNullParameter(questionSearchSessionId, "questionSearchSessionId");
        Intrinsics.checkNotNullParameter(textbookSearchSessionId, "textbookSearchSessionId");
        Intrinsics.checkNotNullParameter(allSearchSessionId, "allSearchSessionId");
        return new SearchSessionData(setSearchSessionId, groupSearchSessionId, userSearchSessionId, questionSearchSessionId, textbookSearchSessionId, allSearchSessionId);
    }

    public final String b(EnumC4478e1 type) {
        Intrinsics.checkNotNullParameter(type, "type");
        int i = WhenMappings.a[type.ordinal()];
        if (i == 1) {
            return this.setSearchSessionId;
        }
        if (i == 2) {
            return this.groupSearchSessionId;
        }
        if (i == 3) {
            return this.userSearchSessionId;
        }
        if (i == 4) {
            return this.questionSearchSessionId;
        }
        if (i == 5) {
            return this.textbookSearchSessionId;
        }
        c.a.d("Incorrect ModelType " + type + ". We only allow Set, Class, Question, Textbook, Term or User here", new Object[0]);
        return "";
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SearchSessionData)) {
            return false;
        }
        SearchSessionData searchSessionData = (SearchSessionData) obj;
        return Intrinsics.b(this.setSearchSessionId, searchSessionData.setSearchSessionId) && Intrinsics.b(this.groupSearchSessionId, searchSessionData.groupSearchSessionId) && Intrinsics.b(this.userSearchSessionId, searchSessionData.userSearchSessionId) && Intrinsics.b(this.questionSearchSessionId, searchSessionData.questionSearchSessionId) && Intrinsics.b(this.textbookSearchSessionId, searchSessionData.textbookSearchSessionId) && Intrinsics.b(this.allSearchSessionId, searchSessionData.allSearchSessionId);
    }

    @NotNull
    public final String getAllSearchSessionId() {
        return this.allSearchSessionId;
    }

    @NotNull
    public final String getGroupSearchSessionId() {
        return this.groupSearchSessionId;
    }

    @NotNull
    public final String getQuestionSearchSessionId() {
        return this.questionSearchSessionId;
    }

    @NotNull
    public final String getSetSearchSessionId() {
        return this.setSearchSessionId;
    }

    @NotNull
    public final String getTextbookSearchSessionId() {
        return this.textbookSearchSessionId;
    }

    @NotNull
    public final String getUserSearchSessionId() {
        return this.userSearchSessionId;
    }

    public final int hashCode() {
        return this.allSearchSessionId.hashCode() + d0.e(d0.e(d0.e(d0.e(this.setSearchSessionId.hashCode() * 31, 31, this.groupSearchSessionId), 31, this.userSearchSessionId), 31, this.questionSearchSessionId), 31, this.textbookSearchSessionId);
    }

    public final String toString() {
        String str = this.setSearchSessionId;
        String str2 = this.groupSearchSessionId;
        String str3 = this.userSearchSessionId;
        String str4 = this.questionSearchSessionId;
        String str5 = this.textbookSearchSessionId;
        String str6 = this.allSearchSessionId;
        StringBuilder sbH = AbstractC0147y.h("SearchSessionData(setSearchSessionId=", str, ", groupSearchSessionId=", str2, ", userSearchSessionId=");
        B.u(sbH, str3, ", questionSearchSessionId=", str4, ", textbookSearchSessionId=");
        return B.j(sbH, str5, ", allSearchSessionId=", str6, ")");
    }

    public SearchSessionData(@NotNull String setSearchSessionId, @NotNull String groupSearchSessionId, @NotNull String userSearchSessionId, @NotNull String questionSearchSessionId, @NotNull String textbookSearchSessionId, @NotNull String allSearchSessionId) {
        Intrinsics.checkNotNullParameter(setSearchSessionId, "setSearchSessionId");
        Intrinsics.checkNotNullParameter(groupSearchSessionId, "groupSearchSessionId");
        Intrinsics.checkNotNullParameter(userSearchSessionId, "userSearchSessionId");
        Intrinsics.checkNotNullParameter(questionSearchSessionId, "questionSearchSessionId");
        Intrinsics.checkNotNullParameter(textbookSearchSessionId, "textbookSearchSessionId");
        Intrinsics.checkNotNullParameter(allSearchSessionId, "allSearchSessionId");
        this.setSearchSessionId = setSearchSessionId;
        this.groupSearchSessionId = groupSearchSessionId;
        this.userSearchSessionId = userSearchSessionId;
        this.questionSearchSessionId = questionSearchSessionId;
        this.textbookSearchSessionId = textbookSearchSessionId;
        this.allSearchSessionId = allSearchSessionId;
    }

    public /* synthetic */ SearchSessionData(String str, String str2, String str3, String str4, String str5, String str6, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? "" : str, (i & 2) != 0 ? "" : str2, (i & 4) != 0 ? "" : str3, (i & 8) != 0 ? "" : str4, (i & 16) != 0 ? "" : str5, (i & 32) != 0 ? "" : str6);
    }
}
