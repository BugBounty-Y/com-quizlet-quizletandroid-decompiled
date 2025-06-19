package com.quizlet.quizletandroid.ui.setcreation.views;

import android.content.Context;
import android.text.SpannableStringBuilder;
import android.text.style.StyleSpan;
import android.view.LayoutInflater;
import android.widget.FrameLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.databinding.b;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a extends FrameLayout {
    public final b a;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public a(@NotNull Context context) {
        this(context, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public final void a(String suggestionText, String str) {
        Intrinsics.checkNotNullParameter(suggestionText, "suggestionText");
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(suggestionText);
        if (str != null) {
            spannableStringBuilder.setSpan(new StyleSpan(1), 0, Math.min(str.length(), suggestionText.length()), 18);
        }
        ((QTextView) this.a.c).setText(spannableStringBuilder);
    }

    @NotNull
    public final String getSuggestionText() {
        return ((QTextView) this.a.c).getText().toString();
    }

    public final void setSuggestionText(@NotNull String suggestionText) {
        Intrinsics.checkNotNullParameter(suggestionText, "suggestionText");
        a(suggestionText, null);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(Context context, int i) {
        super(context, null, 0);
        Intrinsics.checkNotNullParameter(context, "context");
        LayoutInflater.from(context).inflate(R.layout.view_edit_set_suggestion, this);
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.edit_set_suggestion_text, this);
        if (qTextView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(R.id.edit_set_suggestion_text)));
        }
        b bVar = new b(2, qTextView, this);
        Intrinsics.checkNotNullExpressionValue(bVar, "inflate(...)");
        this.a = bVar;
        setPadding(0, 0, 0, (int) getResources().getDimension(R.dimen.quizlet_edge_margin_half));
    }
}
