package com.quizlet.quizletandroid.ui.common.views;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.cardview.widget.CardView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.I;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SimpleTextCardView extends FrameLayout {
    public final com.onetrust.otpublishers.headless.databinding.b a;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public SimpleTextCardView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final QTextView getCardText() {
        QTextView cardText = (QTextView) this.a.c;
        Intrinsics.checkNotNullExpressionValue(cardText, "cardText");
        return cardText;
    }

    private final CardView getCardView() {
        CardView cardView = (CardView) this.a.d;
        Intrinsics.checkNotNullExpressionValue(cardView, "cardView");
        return cardView;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public SimpleTextCardView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public SimpleTextCardView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        View viewInflate = LayoutInflater.from(context).inflate(R.layout.simple_text_card_view, (ViewGroup) this, false);
        addView(viewInflate);
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.cardText, viewInflate);
        if (qTextView != null) {
            CardView cardView = (CardView) viewInflate;
            com.onetrust.otpublishers.headless.databinding.b bVar = new com.onetrust.otpublishers.headless.databinding.b(cardView, qTextView, cardView, 3);
            Intrinsics.checkNotNullExpressionValue(bVar, "inflate(...)");
            this.a = bVar;
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, I.e, 0, 0);
            Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
            if (typedArrayObtainStyledAttributes.hasValue(0)) {
                getCardText().setText(typedArrayObtainStyledAttributes.getText(0));
            }
            if (typedArrayObtainStyledAttributes.hasValue(2)) {
                getCardView().setCardElevation(typedArrayObtainStyledAttributes.getDimension(2, DefinitionKt.NO_Float_VALUE));
            }
            if (typedArrayObtainStyledAttributes.hasValue(1)) {
                getCardView().setBackground(typedArrayObtainStyledAttributes.getDrawable(1));
            }
            typedArrayObtainStyledAttributes.recycle();
            return;
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.cardText)));
    }
}
