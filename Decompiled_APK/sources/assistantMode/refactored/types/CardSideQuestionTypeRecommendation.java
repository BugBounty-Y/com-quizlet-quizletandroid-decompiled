package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.refactored.enums.j;
import assistantMode.refactored.enums.l;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class CardSideQuestionTypeRecommendation implements f {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;
    public final l b;
    public final long c;
    public final j d;
    public final String e;
    public final long f;
    public final AnswerSidePriorities g;
    public final AnswerSidePriorities h;
    public final AnswerSidePriorities i;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return CardSideQuestionTypeRecommendation$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ CardSideQuestionTypeRecommendation(int i, long j, l lVar, long j2, j jVar, String str, long j3, AnswerSidePriorities answerSidePriorities, AnswerSidePriorities answerSidePriorities2, AnswerSidePriorities answerSidePriorities3) {
        if (511 != (i & 511)) {
            AbstractC5047c0.k(i, 511, CardSideQuestionTypeRecommendation$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = lVar;
        this.c = j2;
        this.d = jVar;
        this.e = str;
        this.f = j3;
        this.g = answerSidePriorities;
        this.h = answerSidePriorities2;
        this.i = answerSidePriorities3;
    }

    @Override // assistantMode.refactored.types.f
    public final long a() {
        return this.f;
    }

    @Override // assistantMode.refactored.types.f
    public final long b() {
        return this.a;
    }

    @Override // assistantMode.refactored.types.f
    public final String c() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CardSideQuestionTypeRecommendation)) {
            return false;
        }
        CardSideQuestionTypeRecommendation cardSideQuestionTypeRecommendation = (CardSideQuestionTypeRecommendation) obj;
        return this.a == cardSideQuestionTypeRecommendation.a && this.b == cardSideQuestionTypeRecommendation.b && this.c == cardSideQuestionTypeRecommendation.c && this.d == cardSideQuestionTypeRecommendation.d && Intrinsics.b(this.e, cardSideQuestionTypeRecommendation.e) && this.f == cardSideQuestionTypeRecommendation.f && Intrinsics.b(this.g, cardSideQuestionTypeRecommendation.g) && Intrinsics.b(this.h, cardSideQuestionTypeRecommendation.h) && Intrinsics.b(this.i, cardSideQuestionTypeRecommendation.i);
    }

    public final int hashCode() {
        return this.i.hashCode() + ((this.h.hashCode() + ((this.g.hashCode() + d0.d(d0.e((this.d.hashCode() + d0.d((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31, 31, this.c)) * 31, 31, this.e), 31, this.f)) * 31)) * 31);
    }

    public final String toString() {
        return "CardSideQuestionTypeRecommendation(studiableItemId=" + this.a + ", studiableItemType=" + this.b + ", studiableContainerId=" + this.c + ", studiableContainerType=" + this.d + ", modelVersion=" + this.e + ", predictionTimestamp=" + this.f + ", multipleChoice=" + this.g + ", written=" + this.h + ", revealSelfAssessment=" + this.i + ")";
    }
}
