package com.braze.events;

import com.braze.models.cards.Card;
import com.braze.support.DateTimeUtils;
import java.util.List;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class ContentCardsUpdatedEvent {
    public static final Companion Companion = new Companion(null);
    private final List<Card> contentCards;
    private final boolean isFromOfflineStorage;
    private final long timestampSeconds;
    private final String userId;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final ContentCardsUpdatedEvent getEmptyUpdate() {
            return new ContentCardsUpdatedEvent(K.a, null, DateTimeUtils.nowInSeconds(), true);
        }

        private Companion() {
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public ContentCardsUpdatedEvent(List<? extends Card> contentCards, String str, long j, boolean z) {
        Intrinsics.checkNotNullParameter(contentCards, "contentCards");
        this.contentCards = contentCards;
        this.userId = str;
        this.timestampSeconds = j;
        this.isFromOfflineStorage = z;
    }

    public final List<Card> getAllCards() {
        return CollectionsKt.y0(this.contentCards);
    }

    public final int getCardCount() {
        return this.contentCards.size();
    }

    public final boolean isFromOfflineStorage() {
        return this.isFromOfflineStorage;
    }

    public final boolean isTimestampOlderThan(long j) {
        return TimeUnit.SECONDS.toMillis(this.timestampSeconds + j) < DateTimeUtils.nowInMilliseconds();
    }

    public String toString() {
        return "ContentCardsUpdatedEvent{userId='" + this.userId + "', timestampSeconds=" + this.timestampSeconds + ", isFromOfflineStorage=" + this.isFromOfflineStorage + ", card count=" + getCardCount() + '}';
    }
}
