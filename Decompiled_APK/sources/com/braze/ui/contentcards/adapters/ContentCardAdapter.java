package com.braze.ui.contentcards.adapters;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.RunnableC0133j;
import androidx.camera.core.processing.h;
import androidx.compose.animation.d0;
import androidx.recyclerview.widget.AbstractC1358c;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.AbstractC1389s;
import androidx.recyclerview.widget.C1356b;
import androidx.recyclerview.widget.C1392u;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.LinearLayoutManager;
import com.braze.enums.i;
import com.braze.managers.J;
import com.braze.models.cards.Card;
import com.braze.models.cards.d;
import com.braze.support.BrazeLogger;
import com.braze.ui.contentcards.b;
import com.braze.ui.contentcards.handlers.IContentCardsViewBindingHandler;
import com.braze.ui.contentcards.listeners.IContentCardsActionListener;
import com.braze.ui.contentcards.managers.BrazeContentCardsManager;
import com.braze.ui.contentcards.recycler.ItemTouchHelperAdapter;
import com.braze.ui.contentcards.view.ContentCardViewHolder;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class ContentCardAdapter extends AbstractC1361d0 implements ItemTouchHelperAdapter {

    @NotNull
    private final List<Card> cardData;

    @NotNull
    private final IContentCardsViewBindingHandler contentCardsViewBindingHandler;

    @NotNull
    private final Context context;

    @NotNull
    private final Handler handler;

    @NotNull
    private Set<String> impressedCardIdsInternal;

    @NotNull
    private final LinearLayoutManager layoutManager;

    @Metadata
    public static final class CardListDiffCallback extends AbstractC1389s {

        @NotNull
        private final List<Card> newCards;

        @NotNull
        private final List<Card> oldCards;

        /* JADX WARN: Multi-variable type inference failed */
        public CardListDiffCallback(@NotNull List<? extends Card> oldCards, @NotNull List<? extends Card> newCards) {
            Intrinsics.checkNotNullParameter(oldCards, "oldCards");
            Intrinsics.checkNotNullParameter(newCards, "newCards");
            this.oldCards = oldCards;
            this.newCards = newCards;
        }

        private final boolean doItemsShareIds(int i, int i2) {
            return Intrinsics.b(this.oldCards.get(i).getId(), this.newCards.get(i2).getId());
        }

        @Override // androidx.recyclerview.widget.AbstractC1389s
        public boolean areContentsTheSame(int i, int i2) {
            return doItemsShareIds(i, i2);
        }

        @Override // androidx.recyclerview.widget.AbstractC1389s
        public boolean areItemsTheSame(int i, int i2) {
            return doItemsShareIds(i, i2);
        }

        @Override // androidx.recyclerview.widget.AbstractC1389s
        public int getNewListSize() {
            return this.newCards.size();
        }

        @Override // androidx.recyclerview.widget.AbstractC1389s
        public int getOldListSize() {
            return this.oldCards.size();
        }
    }

    public ContentCardAdapter(@NotNull Context context, @NotNull LinearLayoutManager layoutManager, @NotNull List<Card> cardData, @NotNull IContentCardsViewBindingHandler contentCardsViewBindingHandler) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(layoutManager, "layoutManager");
        Intrinsics.checkNotNullParameter(cardData, "cardData");
        Intrinsics.checkNotNullParameter(contentCardsViewBindingHandler, "contentCardsViewBindingHandler");
        this.context = context;
        this.layoutManager = layoutManager;
        this.cardData = cardData;
        this.contentCardsViewBindingHandler = contentCardsViewBindingHandler;
        this.handler = new Handler(Looper.getMainLooper());
        this.impressedCardIdsInternal = new LinkedHashSet();
        setHasStableIds(true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getCardAtIndex$lambda$7(int i, ContentCardAdapter contentCardAdapter) {
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Cannot return card at index: ", " in cards list of size: ");
        sbV.append(contentCardAdapter.cardData.size());
        return sbV.toString();
    }

    private final boolean isInvalidIndex(int i) {
        return i < 0 || i >= this.cardData.size();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logImpression$lambda$8(Card card) {
        return "Logged impression for card " + card.getId();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logImpression$lambda$9(Card card) {
        return "Already counted impression for card " + card.getId();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String markOnScreenCardsAsRead$lambda$4() {
        return "Card list is empty. Not marking on-screen cards as read.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String markOnScreenCardsAsRead$lambda$5(int i, int i2) {
        return d0.p("Not marking all on-screen cards as read. Either the first or last index is negative. First visible: ", i, " . Last visible: ", i2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void markOnScreenCardsAsRead$lambda$6(int i, int i2, ContentCardAdapter contentCardAdapter) {
        contentCardAdapter.notifyItemRangeChanged(i2, (i - i2) + 1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onItemDismiss$lambda$0(int i, ContentCardAdapter contentCardAdapter) {
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Cannot dismiss card at index: ", " in cards list of size: ");
        sbV.append(contentCardAdapter.cardData.size());
        return sbV.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onViewAttachedToWindow$lambda$1(int i) {
        return AbstractC0147y.c(i, "The card at position ", " isn't on screen or does not have a valid adapter position. Not logging impression.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onViewDetachedFromWindow$lambda$2(int i) {
        return AbstractC0147y.c(i, "The card at position ", " isn't on screen or does not have a valid adapter position. Not marking as read.");
    }

    public final Card getCardAtIndex(int i) {
        if (!isInvalidIndex(i)) {
            return this.cardData.get(i);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new a(i, 1, this), 7, (Object) null);
        return null;
    }

    @NotNull
    public final List<String> getImpressedCardIds() {
        return CollectionsKt.w0(this.impressedCardIdsInternal);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public int getItemCount() {
        return this.cardData.size();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public long getItemId(int i) {
        String id;
        Card cardAtIndex = getCardAtIndex(i);
        if (cardAtIndex == null || (id = cardAtIndex.getId()) == null) {
            return 0L;
        }
        return id.hashCode();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public int getItemViewType(int i) {
        return this.contentCardsViewBindingHandler.getItemViewType(this.context, this.cardData, i);
    }

    public final boolean isAdapterPositionOnScreen(int i) {
        int iS0 = this.layoutManager.S0();
        LinearLayoutManager linearLayoutManager = this.layoutManager;
        View viewW0 = linearLayoutManager.W0(0, linearLayoutManager.v(), true, false);
        return Math.min(iS0, viewW0 == null ? -1 : AbstractC1381n0.K(viewW0)) <= i && i <= Math.max(this.layoutManager.U0(), this.layoutManager.T0());
    }

    public final boolean isControlCardAtPosition(int i) {
        Card cardAtIndex = getCardAtIndex(i);
        return cardAtIndex != null && cardAtIndex.isControl();
    }

    @Override // com.braze.ui.contentcards.recycler.ItemTouchHelperAdapter
    public boolean isItemDismissable(int i) {
        if (this.cardData.isEmpty() || isInvalidIndex(i)) {
            return false;
        }
        return this.cardData.get(i).isDismissibleByUser();
    }

    public final void logImpression(Card card) {
        if (card == null) {
            return;
        }
        if (this.impressedCardIdsInternal.contains(card.getId())) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new d(card, 7), 6, (Object) null);
        } else {
            card.logImpression();
            this.impressedCardIdsInternal.add(card.getId());
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new d(card, 6), 6, (Object) null);
        }
        if (card.getViewed()) {
            return;
        }
        card.setViewed(true);
    }

    public final void markOnScreenCardsAsRead() {
        if (this.cardData.isEmpty()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new b(4), 7, (Object) null);
            return;
        }
        int iS0 = this.layoutManager.S0();
        int iU0 = this.layoutManager.U0();
        if (iS0 < 0 || iU0 < 0) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new J(iS0, iU0, 5), 7, (Object) null);
            return;
        }
        if (iS0 <= iU0) {
            int i = iS0;
            while (true) {
                Card cardAtIndex = getCardAtIndex(i);
                if (cardAtIndex != null) {
                    cardAtIndex.setIndicatorHighlighted(true);
                }
                if (i == iU0) {
                    break;
                } else {
                    i++;
                }
            }
        }
        this.handler.post(new h(iU0, iS0, this));
    }

    @Override // com.braze.ui.contentcards.recycler.ItemTouchHelperAdapter
    public void onItemDismiss(int i) {
        if (isInvalidIndex(i)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new a(i, 0, this), 7, (Object) null);
            return;
        }
        Card cardRemove = this.cardData.remove(i);
        cardRemove.setDismissed(true);
        notifyItemRemoved(i);
        IContentCardsActionListener contentCardsActionListener = BrazeContentCardsManager.Companion.getInstance().getContentCardsActionListener();
        if (contentCardsActionListener != null) {
            contentCardsActionListener.onContentCardDismissed(this.context, cardRemove);
        }
    }

    public final synchronized void replaceCards(@NotNull List<? extends Card> newCardData) {
        Intrinsics.checkNotNullParameter(newCardData, "newCardData");
        C1392u c1392uC = AbstractC1358c.c(new CardListDiffCallback(this.cardData, newCardData));
        Intrinsics.checkNotNullExpressionValue(c1392uC, "calculateDiff(...)");
        this.cardData.clear();
        this.cardData.addAll(newCardData);
        c1392uC.a(new C1356b(this));
    }

    public final void setImpressedCardIds(@NotNull List<String> impressedCardIds) {
        Intrinsics.checkNotNullParameter(impressedCardIds, "impressedCardIds");
        this.impressedCardIdsInternal = CollectionsKt.z0(impressedCardIds);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public void onBindViewHolder(@NotNull ContentCardViewHolder viewHolder, int i) {
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        this.contentCardsViewBindingHandler.onBindViewHolder(this.context, this.cardData, viewHolder, i);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    @NotNull
    public ContentCardViewHolder onCreateViewHolder(@NotNull ViewGroup viewGroup, int i) {
        Intrinsics.checkNotNullParameter(viewGroup, "viewGroup");
        return this.contentCardsViewBindingHandler.onCreateViewHolder(this.context, this.cardData, viewGroup, i);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public void onViewAttachedToWindow(@NotNull ContentCardViewHolder holder) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        super.onViewAttachedToWindow((F0) holder);
        if (this.cardData.isEmpty()) {
            return;
        }
        int bindingAdapterPosition = holder.getBindingAdapterPosition();
        if (bindingAdapterPosition == -1 || !isAdapterPositionOnScreen(bindingAdapterPosition)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new i(bindingAdapterPosition, 18), 6, (Object) null);
        } else {
            logImpression(getCardAtIndex(bindingAdapterPosition));
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public void onViewDetachedFromWindow(@NotNull ContentCardViewHolder holder) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        super.onViewDetachedFromWindow((F0) holder);
        if (this.cardData.isEmpty()) {
            return;
        }
        int bindingAdapterPosition = holder.getBindingAdapterPosition();
        if (bindingAdapterPosition == -1 || !isAdapterPositionOnScreen(bindingAdapterPosition)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new i(bindingAdapterPosition, 19), 6, (Object) null);
            return;
        }
        Card cardAtIndex = getCardAtIndex(bindingAdapterPosition);
        if (cardAtIndex == null || cardAtIndex.isIndicatorHighlighted()) {
            return;
        }
        cardAtIndex.setIndicatorHighlighted(true);
        this.handler.post(new RunnableC0133j(this, bindingAdapterPosition, 4));
    }
}
