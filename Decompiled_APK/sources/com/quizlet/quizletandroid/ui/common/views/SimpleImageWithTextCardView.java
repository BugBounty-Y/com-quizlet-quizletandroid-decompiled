package com.quizlet.quizletandroid.ui.common.views;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.cardview.widget.CardView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.features.infra.legacyadapter.databinding.f;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.I;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SimpleImageWithTextCardView extends FrameLayout {
    public final f a;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public SimpleImageWithTextCardView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final ImageView getCardIcon() {
        ImageView cardIcon = (ImageView) this.a.c;
        Intrinsics.checkNotNullExpressionValue(cardIcon, "cardIcon");
        return cardIcon;
    }

    private final QTextView getCardText() {
        QTextView cardText = (QTextView) this.a.d;
        Intrinsics.checkNotNullExpressionValue(cardText, "cardText");
        return cardText;
    }

    private final CardView getCardView() {
        CardView cardView = (CardView) this.a.e;
        Intrinsics.checkNotNullExpressionValue(cardView, "cardView");
        return cardView;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public SimpleImageWithTextCardView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public SimpleImageWithTextCardView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        View viewInflate = LayoutInflater.from(context).inflate(R.layout.simple_image_with_text_card_view, (ViewGroup) this, false);
        addView(viewInflate);
        int i2 = R.id.cardIcon;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.cardIcon, viewInflate);
        if (imageView != null) {
            i2 = R.id.cardText;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.cardText, viewInflate);
            if (qTextView != null) {
                CardView cardView = (CardView) viewInflate;
                f fVar = new f(cardView, imageView, qTextView, cardView, 9);
                Intrinsics.checkNotNullExpressionValue(fVar, "inflate(...)");
                this.a = fVar;
                TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, I.d, 0, 0);
                Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
                if (typedArrayObtainStyledAttributes.hasValue(1)) {
                    getCardText().setText(typedArrayObtainStyledAttributes.getText(1));
                }
                if (typedArrayObtainStyledAttributes.hasValue(0)) {
                    getCardIcon().setImageDrawable(typedArrayObtainStyledAttributes.getDrawable(0));
                }
                if (typedArrayObtainStyledAttributes.hasValue(3)) {
                    getCardView().setCardElevation(typedArrayObtainStyledAttributes.getDimension(3, DefinitionKt.NO_Float_VALUE));
                }
                if (typedArrayObtainStyledAttributes.hasValue(2)) {
                    getCardView().setBackground(typedArrayObtainStyledAttributes.getDrawable(2));
                }
                typedArrayObtainStyledAttributes.recycle();
                return;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i2)));
    }
}
