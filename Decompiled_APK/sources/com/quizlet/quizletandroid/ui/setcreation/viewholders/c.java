package com.quizlet.quizletandroid.ui.setcreation.viewholders;

import android.view.View;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.icon.IconFontTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.I;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends F0 {
    public static final /* synthetic */ int b = 0;
    public final com.quizlet.quizletandroid.ui.setcreation.adapters.f a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(com.quizlet.quizletandroid.ui.setcreation.adapters.f adapter, View itemView) {
        super(itemView);
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        this.a = adapter;
        IconFontTextView iconFontTextView = (IconFontTextView) AbstractC3375o2.c(R.id.edit_set_new_card_button, itemView);
        if (iconFontTextView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(itemView.getResources().getResourceName(R.id.edit_set_new_card_button)));
        }
        Intrinsics.checkNotNullExpressionValue(new I((FrameLayout) itemView, iconFontTextView), "bind(...)");
        iconFontTextView.setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 15));
    }
}
