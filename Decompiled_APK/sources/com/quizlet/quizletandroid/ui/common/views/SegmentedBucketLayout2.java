package com.quizlet.quizletandroid.ui.common.views;

import android.content.Context;
import android.content.res.Resources;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.cardview.widget.CardView;
import com.quizlet.features.infra.legacyadapter.databinding.h;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SegmentedBucketLayout2 extends LinearLayout {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SegmentedBucketLayout2(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        setOrientation(0);
        setShowDividers(2);
        setDividerDrawable(getContext().getDrawable(R.drawable.spacer_8dp_horizontal));
    }

    public final void a(int i, int i2, int i3, int i4, boolean z, View.OnClickListener onClickListener, o tag) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(onClickListener, "onClickListener");
        Intrinsics.checkNotNullParameter(tag, "tag");
        h hVarB = h.b(LayoutInflater.from(getContext()).inflate(R.layout.segmented_bucket_2, (ViewGroup) this, false));
        Intrinsics.checkNotNullExpressionValue(hVarB, "inflate(...)");
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        int iA = com.quizlet.themes.extensions.a.a(context, i3);
        ((QTextView) hVarB.d).setText(getContext().getResources().getQuantityString(i, i4, Integer.valueOf(i4)));
        String quantityString = getContext().getResources().getQuantityString(i2, i4, Integer.valueOf(i4));
        CardView cardView = (CardView) hVarB.e;
        cardView.setContentDescription(quantityString);
        QTextView qTextView = (QTextView) hVarB.b;
        qTextView.setTextColor(iA);
        qTextView.setText(String.valueOf(i4));
        ImageView imageView = (ImageView) hVarB.c;
        imageView.setVisibility(8);
        imageView.setImageDrawable(null);
        if (z) {
            ((View) hVarB.f).setBackgroundColor(iA);
            cardView.setCardElevation(getResources().getDimensionPixelSize(R.dimen.bucket_elevation_selected));
        }
        cardView.setOnClickListener(new com.braze.ui.inappmessage.views.a(21, onClickListener, this));
        cardView.setTag(tag);
        addView(cardView);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SegmentedBucketLayout2(@NotNull Context context, @NotNull AttributeSet attrs) {
        super(context, attrs);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attrs, "attrs");
        setOrientation(0);
        setShowDividers(2);
        setDividerDrawable(getContext().getDrawable(R.drawable.spacer_8dp_horizontal));
    }
}
