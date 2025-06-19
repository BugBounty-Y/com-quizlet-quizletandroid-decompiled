package com.braze.ui.contentcards.view;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import com.braze.models.cards.Card;
import com.braze.models.cards.ImageOnlyCard;
import com.braze.ui.R$id;
import com.braze.ui.R$layout;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class ImageOnlyContentCardView extends BaseContentCardView<ImageOnlyCard> {

    @Metadata
    public final class ViewHolder extends ContentCardViewHolder {
        private final ImageView imageView;
        final /* synthetic */ ImageOnlyContentCardView this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public ViewHolder(@NotNull ImageOnlyContentCardView imageOnlyContentCardView, View view) {
            super(view, imageOnlyContentCardView.isUnreadIndicatorEnabled());
            Intrinsics.checkNotNullParameter(view, "view");
            this.this$0 = imageOnlyContentCardView;
            this.imageView = (ImageView) view.findViewById(R$id.com_braze_content_cards_image_only_card_image);
        }

        public final ImageView getImageView() {
            return this.imageView;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ImageOnlyContentCardView(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @Override // com.braze.ui.contentcards.view.BaseContentCardView
    public void bindViewHolder(@NotNull ContentCardViewHolder viewHolder, @NotNull Card card) {
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        Intrinsics.checkNotNullParameter(card, "card");
        if (card instanceof ImageOnlyCard) {
            super.bindViewHolder(viewHolder, card);
            ImageOnlyCard imageOnlyCard = (ImageOnlyCard) card;
            setOptionalCardImage(((ViewHolder) viewHolder).getImageView(), imageOnlyCard.getAspectRatio(), imageOnlyCard.getImageUrl(), card);
        }
    }

    @Override // com.braze.ui.contentcards.view.BaseContentCardView
    @NotNull
    public ContentCardViewHolder createViewHolder(@NotNull ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(viewGroup, "viewGroup");
        View viewInflate = LayoutInflater.from(viewGroup.getContext()).inflate(R$layout.com_braze_image_only_content_card, viewGroup, false);
        Intrinsics.d(viewInflate);
        setViewBackground(viewInflate);
        return new ViewHolder(this, viewInflate);
    }
}
