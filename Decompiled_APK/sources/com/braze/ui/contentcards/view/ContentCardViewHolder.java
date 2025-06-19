package com.braze.ui.contentcards.view;

import android.text.TextUtils;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import com.braze.ui.R$drawable;
import com.braze.ui.R$id;
import java.util.Locale;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class ContentCardViewHolder extends F0 {
    private final TextView actionHint;
    private final ImageView pinnedIcon;
    private final View unreadBar;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ContentCardViewHolder(@NotNull View view, boolean z) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        View viewFindViewById = view.findViewById(R$id.com_braze_content_cards_unread_bar);
        this.unreadBar = viewFindViewById;
        this.pinnedIcon = (ImageView) view.findViewById(R$id.com_braze_content_cards_pinned_icon);
        this.actionHint = (TextView) view.findViewById(R$id.com_braze_content_cards_action_hint);
        if (!z) {
            if (viewFindViewById != null) {
                viewFindViewById.setVisibility(8);
            }
        } else {
            if (viewFindViewById != null) {
                viewFindViewById.setVisibility(0);
            }
            if (viewFindViewById != null) {
                viewFindViewById.setBackground(view.getContext().getResources().getDrawable(R$drawable.com_braze_content_cards_unread_bar_background));
            }
        }
    }

    public final void setActionHintText(@NotNull String text) {
        Intrinsics.checkNotNullParameter(text, "text");
        TextView textView = this.actionHint;
        if (textView != null) {
            textView.setText(text);
        }
    }

    public final void setActionHintVisible(boolean z) {
        TextView textView = this.actionHint;
        if (textView != null) {
            textView.setVisibility(z ? 0 : 8);
        }
    }

    public final void setPinnedIconVisible(boolean z) {
        ImageView imageView;
        ImageView imageView2 = this.pinnedIcon;
        if (imageView2 != null) {
            imageView2.setVisibility(z ? 0 : 8);
        }
        if (z) {
            Locale locale = Locale.getDefault();
            Intrinsics.checkNotNullExpressionValue(locale, "getDefault(...)");
            if (TextUtils.getLayoutDirectionFromLocale(locale) != 1 || (imageView = this.pinnedIcon) == null) {
                return;
            }
            imageView.setScaleX(-1.0f);
        }
    }

    public final void setUnreadBarVisible(boolean z) {
        View view = this.unreadBar;
        if (view != null) {
            view.setVisibility(z ? 0 : 8);
        }
    }
}
