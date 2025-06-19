package com.braze.ui.contentcards.view;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import com.braze.models.cards.CaptionedImageCard;
import com.braze.models.cards.Card;
import com.braze.ui.R$id;
import com.braze.ui.R$layout;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class CaptionedImageContentCardView extends BaseContentCardView<CaptionedImageCard> {

    @Metadata
    public final class ViewHolder extends ContentCardViewHolder {
        private final TextView description;
        private final ImageView imageView;
        final /* synthetic */ CaptionedImageContentCardView this$0;
        private final TextView title;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public ViewHolder(@NotNull CaptionedImageContentCardView captionedImageContentCardView, View view) {
            super(view, captionedImageContentCardView.isUnreadIndicatorEnabled());
            Intrinsics.checkNotNullParameter(view, "view");
            this.this$0 = captionedImageContentCardView;
            this.title = (TextView) view.findViewById(R$id.com_braze_content_cards_captioned_image_title);
            this.description = (TextView) view.findViewById(R$id.com_braze_content_cards_captioned_image_description);
            this.imageView = (ImageView) view.findViewById(R$id.com_braze_content_cards_captioned_image_card_image);
        }

        public final TextView getDescription() {
            return this.description;
        }

        public final ImageView getImageView() {
            return this.imageView;
        }

        public final TextView getTitle() {
            return this.title;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CaptionedImageContentCardView(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @Override // com.braze.ui.contentcards.view.BaseContentCardView
    public void bindViewHolder(@NotNull ContentCardViewHolder viewHolder, @NotNull Card card) {
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        Intrinsics.checkNotNullParameter(card, "card");
        if (card instanceof CaptionedImageCard) {
            super.bindViewHolder(viewHolder, card);
            ViewHolder viewHolder2 = (ViewHolder) viewHolder;
            TextView title = viewHolder2.getTitle();
            if (title != null) {
                setOptionalTextView(title, ((CaptionedImageCard) card).getTitle());
            }
            TextView description = viewHolder2.getDescription();
            if (description != null) {
                setOptionalTextView(description, ((CaptionedImageCard) card).getDescription());
            }
            CaptionedImageCard captionedImageCard = (CaptionedImageCard) card;
            String domain = captionedImageCard.getDomain();
            String url = (domain == null || StringsKt.O(domain)) ? captionedImageCard.getUrl() : captionedImageCard.getDomain();
            if (url != null) {
                viewHolder2.setActionHintText(url);
            }
            setOptionalCardImage(viewHolder2.getImageView(), captionedImageCard.getAspectRatio(), captionedImageCard.getImageUrl(), card);
            viewHolder.itemView.setContentDescription(captionedImageCard.getTitle() + " .  " + captionedImageCard.getDescription());
        }
    }

    @Override // com.braze.ui.contentcards.view.BaseContentCardView
    @NotNull
    public ContentCardViewHolder createViewHolder(@NotNull ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(viewGroup, "viewGroup");
        View viewInflate = LayoutInflater.from(viewGroup.getContext()).inflate(R$layout.com_braze_captioned_image_content_card, viewGroup, false);
        Intrinsics.d(viewInflate);
        setViewBackground(viewInflate);
        return new ViewHolder(this, viewInflate);
    }
}
