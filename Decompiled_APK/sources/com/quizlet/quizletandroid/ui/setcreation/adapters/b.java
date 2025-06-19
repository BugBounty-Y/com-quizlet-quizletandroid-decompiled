package com.quizlet.quizletandroid.ui.setcreation.adapters;

import android.view.View;
import androidx.recyclerview.widget.F0;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.databinding.m0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes3.dex */
public final class b extends F0 {
    public final u a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(View itemView) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        this.a = l.b(new com.quizlet.features.infra.legacyadapter.viewholder.a(itemView, 3));
    }

    public final void c(int i, boolean z) {
        u uVar = this.a;
        QTextView editSetLanguageHeader = ((m0) uVar.getValue()).c;
        Intrinsics.checkNotNullExpressionValue(editSetLanguageHeader, "editSetLanguageHeader");
        editSetLanguageHeader.setText(i);
        View editSetLanguageGap = ((m0) uVar.getValue()).b;
        Intrinsics.checkNotNullExpressionValue(editSetLanguageGap, "editSetLanguageGap");
        editSetLanguageGap.setVisibility(z ? 8 : 0);
    }
}
