package com.quizlet.quizletandroid.ui.activitycenter.views;

import android.content.Context;
import android.os.Parcel;
import android.view.ViewGroup;
import androidx.collection.C0208f;
import com.braze.enums.CardType;
import com.braze.models.cards.Card;
import com.braze.ui.contentcards.handlers.IContentCardsViewBindingHandler;
import com.braze.ui.contentcards.view.BaseContentCardView;
import com.braze.ui.contentcards.view.ContentCardViewHolder;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ActivityCenterViewBindingHandler implements IContentCardsViewBindingHandler {

    @NotNull
    public static final a CREATOR = new a();
    public final C0208f a = new C0208f(0);
    public com.quizlet.qutils.image.loading.a b;

    public final BaseContentCardView a(Context context, CardType cardType) {
        C0208f c0208f = this.a;
        if (!c0208f.containsKey(cardType)) {
            int i = b.a[cardType.ordinal()];
            if (i != 1 && i != 2) {
                throw new IllegalArgumentException("Unsupported cardType: (" + cardType + ")");
            }
            com.quizlet.qutils.image.loading.a aVar = this.b;
            if (aVar == null) {
                Intrinsics.m("imageLoader");
                throw null;
            }
            c0208f.put(cardType, new d(context, aVar));
        }
        return (BaseContentCardView) V.d(cardType, c0208f);
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // com.braze.ui.contentcards.handlers.IContentCardsViewBindingHandler
    public final int getItemViewType(Context context, List cards, int i) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(cards, "cards");
        return ((Card) cards.get(i)).getCardType().getValue();
    }

    @Override // com.braze.ui.contentcards.handlers.IContentCardsViewBindingHandler
    public final void onBindViewHolder(Context context, List cards, ContentCardViewHolder viewHolder, int i) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(cards, "cards");
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        Card card = (Card) cards.get(i);
        a(context, card.getCardType()).bindViewHolder(viewHolder, card);
    }

    @Override // com.braze.ui.contentcards.handlers.IContentCardsViewBindingHandler
    public final ContentCardViewHolder onCreateViewHolder(Context context, List cards, ViewGroup viewGroup, int i) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(cards, "cards");
        Intrinsics.checkNotNullParameter(viewGroup, "viewGroup");
        return a(context, CardType.values()[i]).createViewHolder(viewGroup);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
    }
}
