package com.quizlet.quizletandroid.ui.setcreation.views;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.appcompat.widget.C0122z;
import androidx.cardview.widget.CardView;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class OcrCardView extends FrameLayout {
    public final QFormField a;
    public final QFormField b;
    public final CardView c;
    public final CardView d;
    public final ImageView e;
    public final QTextView f;
    public final ViewGroup g;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public OcrCardView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public final void a(EditText focusedView, Function0 onClearIconClicked) {
        Intrinsics.checkNotNullParameter(focusedView, "focusedView");
        Intrinsics.checkNotNullParameter(onClearIconClicked, "onClearIconClicked");
        this.a.setFormFieldIcon(new C0122z(focusedView, R.string.ocr_card_view_clear_icon_term_field_content_description, onClearIconClicked));
        this.b.setFormFieldIcon(new C0122z(focusedView, R.string.ocr_card_view_clear_icon_definition_field_content_description, onClearIconClicked));
    }

    @NotNull
    public final QFormField getDefinitionFormField() {
        return this.b;
    }

    @NotNull
    public final QFormField getWordFormField() {
        return this.a;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public OcrCardView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public OcrCardView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        View.inflate(context, R.layout.view_ocr_card, this);
        QFormField qFormField = (QFormField) findViewById(R.id.wordField);
        this.a = qFormField;
        QFormField qFormField2 = (QFormField) findViewById(R.id.definitionField);
        this.b = qFormField2;
        this.c = (CardView) findViewById(R.id.cardView);
        this.d = (CardView) findViewById(R.id.successCardView);
        this.e = (ImageView) findViewById(R.id.saveCardCheck);
        this.f = (QTextView) findViewById(R.id.cardSavedDescription);
        this.g = (ViewGroup) findViewById(R.id.rootContainer);
        qFormField.setMaxLines(2);
        qFormField2.setMaxLines(2);
        Context context2 = getContext();
        Integer numValueOf = context2 != null ? Integer.valueOf(com.quizlet.themes.extensions.a.a(context2, R.attr.stateNormal)) : null;
        Intrinsics.d(numValueOf);
        int iIntValue = numValueOf.intValue();
        qFormField.setFormIconTintColor(iIntValue);
        qFormField2.setFormIconTintColor(iIntValue);
    }
}
