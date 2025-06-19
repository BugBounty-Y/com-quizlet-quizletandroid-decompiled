package assistantMode.exceptions;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a extends Throwable {
    public final String a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(Double[] answerHistoryStudiableItemIds, Double[] remainingStudiableItemIdsInRound, Double[] incorrectStudiableItemIdsInRound, Double[] studiableItemIdsAnsweredSinceRoundStart) {
        super("Answer does not correspond to current question");
        Intrinsics.checkNotNullParameter("Answer does not correspond to current question", "message");
        Intrinsics.checkNotNullParameter(answerHistoryStudiableItemIds, "answerHistoryStudiableItemIds");
        Intrinsics.checkNotNullParameter(remainingStudiableItemIdsInRound, "remainingStudiableItemIdsInRound");
        Intrinsics.checkNotNullParameter(incorrectStudiableItemIdsInRound, "incorrectStudiableItemIdsInRound");
        Intrinsics.checkNotNullParameter(studiableItemIdsAnsweredSinceRoundStart, "studiableItemIdsAnsweredSinceRoundStart");
        this.a = "Answer does not correspond to current question";
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        return this.a;
    }
}
