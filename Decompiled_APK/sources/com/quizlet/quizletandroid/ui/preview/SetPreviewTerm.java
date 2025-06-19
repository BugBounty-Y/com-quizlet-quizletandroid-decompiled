package com.quizlet.quizletandroid.ui.preview;

import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.j0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SetPreviewTerm extends ConstraintLayout {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SetPreviewTerm(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        LayoutInflater.from(getContext()).inflate(R.layout.search_set_preview_term, (ViewGroup) this, true);
        j0.a(this);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SetPreviewTerm(@NotNull Context context, @NotNull AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attributeSet, "attributeSet");
        LayoutInflater.from(getContext()).inflate(R.layout.search_set_preview_term, (ViewGroup) this, true);
        j0.a(this);
    }
}
