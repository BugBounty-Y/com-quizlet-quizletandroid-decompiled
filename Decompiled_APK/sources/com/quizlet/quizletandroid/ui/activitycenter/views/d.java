package com.quizlet.quizletandroid.ui.activitycenter.views;

import android.content.Context;
import android.content.res.Resources;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import com.braze.models.cards.Card;
import com.braze.models.cards.ShortNewsCard;
import com.braze.models.cards.TextAnnouncementCard;
import com.braze.ui.contentcards.view.BaseContentCardView;
import com.braze.ui.contentcards.view.ContentCardViewHolder;
import com.braze.ui.widget.BaseCardView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends BaseContentCardView {
    public final com.quizlet.qutils.image.loading.a a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(Context context, com.quizlet.qutils.image.loading.a imageLoader) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        this.a = imageLoader;
    }

    @Override // com.braze.ui.contentcards.view.BaseContentCardView
    public final void bindViewHolder(ContentCardViewHolder viewHolder, Card card) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        Intrinsics.checkNotNullParameter(card, "card");
        if (!(viewHolder instanceof e)) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("viewHolder must be type (ClassicCardViewHolder). viewHolder: (", viewHolder.getClass().getSimpleName(), ")").toString());
        }
        super.bindViewHolder(viewHolder, card);
        boolean z = true;
        boolean z2 = BaseCardView.getUriActionForCard(card) != null;
        e eVar = (e) viewHolder;
        eVar.getClass();
        Intrinsics.checkNotNullParameter(card, "card");
        if (!card.isClicked() && (z2 || !card.isIndicatorHighlighted())) {
            z = false;
        }
        eVar.itemView.setBackgroundResource(!z ? R.drawable.activity_center_card_unread_background : R.drawable.activity_center_card_read_background);
        boolean z3 = card instanceof ShortNewsCard;
        ImageView imageView = eVar.c;
        if (z3) {
            ShortNewsCard shortNewsCard = (ShortNewsCard) card;
            com.quizlet.data.repository.widget.b bVarP = ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) eVar.a).a(eVar.itemView.getContext()).p(shortNewsCard.getImageUrl());
            bVarP.d();
            bVarP.o(imageView);
            eVar.c(card.getCreated(), shortNewsCard.getDescription(), shortNewsCard.getTitle());
        } else {
            if (!(card instanceof TextAnnouncementCard)) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.B("Unsupported card: (", card.getClass().getSimpleName(), ")"));
            }
            Context context = eVar.itemView.getContext();
            Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
            imageView.setImageDrawable(com.quizlet.themes.extensions.a.c(context, R.drawable.activity_center_image_placeholder, R.attr.RefColorGray400));
            TextAnnouncementCard textAnnouncementCard = (TextAnnouncementCard) card;
            eVar.c(card.getCreated(), textAnnouncementCard.getDescription(), textAnnouncementCard.getTitle());
        }
        Intrinsics.checkNotNullParameter(card, "<this>");
        String value = card.getExtras().get("secondaryImageType");
        com.quizlet.quizletandroid.ui.activitycenter.models.b bVar = null;
        if (value != null) {
            com.quizlet.quizletandroid.ui.activitycenter.models.b.c.getClass();
            Intrinsics.checkNotNullParameter(value, "value");
            com.quizlet.quizletandroid.ui.activitycenter.models.b[] bVarArrValues = com.quizlet.quizletandroid.ui.activitycenter.models.b.values();
            int length = bVarArrValues.length;
            int i = 0;
            while (true) {
                if (i >= length) {
                    break;
                }
                com.quizlet.quizletandroid.ui.activitycenter.models.b bVar2 = bVarArrValues[i];
                if (bVar2.a.equals(value)) {
                    bVar = bVar2;
                    break;
                }
                i++;
            }
        }
        FrameLayout frameLayout = eVar.b;
        ImageView imageView2 = eVar.d;
        if (bVar == null) {
            int dimensionPixelSize = eVar.itemView.getContext().getResources().getDimensionPixelSize(R.dimen.activity_center_classic_card_image_size);
            ViewGroup.LayoutParams layoutParams = frameLayout.getLayoutParams();
            layoutParams.width = dimensionPixelSize;
            layoutParams.height = dimensionPixelSize;
            imageView2.setVisibility(8);
            return;
        }
        int dimensionPixelSize2 = eVar.itemView.getContext().getResources().getDimensionPixelSize(R.dimen.activity_center_classic_card_image_size_with_secondary);
        ViewGroup.LayoutParams layoutParams2 = frameLayout.getLayoutParams();
        layoutParams2.width = dimensionPixelSize2;
        layoutParams2.height = dimensionPixelSize2;
        imageView2.setVisibility(0);
        imageView2.setImageResource(bVar.b);
    }

    @Override // com.braze.ui.contentcards.view.BaseContentCardView
    public final ContentCardViewHolder createViewHolder(ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(viewGroup, "viewGroup");
        View viewInflate = LayoutInflater.from(viewGroup.getContext()).inflate(R.layout.item_activity_center_classic_card, viewGroup, false);
        Intrinsics.checkNotNullExpressionValue(viewInflate, "inflate(...)");
        return new e(viewInflate, isUnreadIndicatorEnabled(), this.a);
    }
}
