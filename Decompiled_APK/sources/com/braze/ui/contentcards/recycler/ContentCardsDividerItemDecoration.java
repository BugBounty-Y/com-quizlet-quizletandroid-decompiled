package com.braze.ui.contentcards.recycler;

import android.content.Context;
import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.AbstractC1375k0;
import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.RecyclerView;
import com.braze.ui.R$dimen;
import com.braze.ui.contentcards.adapters.ContentCardAdapter;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class ContentCardsDividerItemDecoration extends AbstractC1375k0 {

    @NotNull
    private final Context appContext;
    private final int contentCardsItemMaxWidth;
    private final int itemDividerHeight;

    public ContentCardsDividerItemDecoration(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Context applicationContext = context.getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
        this.appContext = applicationContext;
        this.itemDividerHeight = applicationContext.getResources().getDimensionPixelSize(R$dimen.com_braze_content_cards_divider_height);
        this.contentCardsItemMaxWidth = applicationContext.getResources().getDimensionPixelSize(R$dimen.com_braze_content_cards_max_width);
    }

    private final int getSidePaddingValue(int i) {
        int i2 = (i - this.contentCardsItemMaxWidth) / 2;
        if (i2 < 0) {
            return 0;
        }
        return i2;
    }

    @Override // androidx.recyclerview.widget.AbstractC1375k0
    public void getItemOffsets(@NotNull Rect itemViewOutputRect, @NotNull View view, @NotNull RecyclerView parent, @NotNull B0 state) {
        boolean zIsControlCardAtPosition;
        Intrinsics.checkNotNullParameter(itemViewOutputRect, "itemViewOutputRect");
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(parent, "parent");
        Intrinsics.checkNotNullParameter(state, "state");
        super.getItemOffsets(itemViewOutputRect, view, parent, state);
        parent.getClass();
        F0 f0P = RecyclerView.P(view);
        int absoluteAdapterPosition = f0P != null ? f0P.getAbsoluteAdapterPosition() : -1;
        if (parent.getAdapter() instanceof ContentCardAdapter) {
            AbstractC1361d0 adapter = parent.getAdapter();
            Intrinsics.e(adapter, "null cannot be cast to non-null type com.braze.ui.contentcards.adapters.ContentCardAdapter");
            zIsControlCardAtPosition = ((ContentCardAdapter) adapter).isControlCardAtPosition(absoluteAdapterPosition);
        } else {
            zIsControlCardAtPosition = false;
        }
        itemViewOutputRect.top = absoluteAdapterPosition == 0 ? this.itemDividerHeight : 0;
        itemViewOutputRect.bottom = zIsControlCardAtPosition ? 0 : this.itemDividerHeight;
        int sidePaddingValue = getSidePaddingValue(parent.getWidth());
        itemViewOutputRect.left = sidePaddingValue;
        itemViewOutputRect.right = sidePaddingValue;
    }
}
