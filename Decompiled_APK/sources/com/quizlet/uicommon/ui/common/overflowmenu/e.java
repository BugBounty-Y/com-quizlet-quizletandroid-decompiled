package com.quizlet.uicommon.ui.common.overflowmenu;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.data.model.A0;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.views.QuizletPlusBadge;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends com.quizlet.baserecyclerview.c {
    public final com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(View view, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a clickCallback) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(clickCallback, "clickCallback");
        this.d = clickCallback;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        int i = R.id.itemIcon;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.itemIcon, view);
        if (imageView != null) {
            i = R.id.itemText;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.itemText, view);
            if (qTextView != null) {
                i = R.id.lockedBadge;
                QuizletPlusBadge quizletPlusBadge = (QuizletPlusBadge) AbstractC3375o2.c(R.id.lockedBadge, view);
                if (quizletPlusBadge != null) {
                    i = R.id.newLabel;
                    QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.newLabel, view);
                    if (qTextView2 != null) {
                        com.quizlet.quizletandroid.ui.common.databinding.e eVar = new com.quizlet.quizletandroid.ui.common.databinding.e((ConstraintLayout) view, imageView, qTextView, quizletPlusBadge, qTextView2);
                        Intrinsics.checkNotNullExpressionValue(eVar, "bind(...)");
                        return eVar;
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(f item) {
        Intrinsics.checkNotNullParameter(item, "item");
        this.itemView.setOnClickListener(new com.braze.ui.inappmessage.views.a(28, item, this));
        ImageView itemIcon = ((com.quizlet.quizletandroid.ui.common.databinding.e) e()).b;
        Intrinsics.checkNotNullExpressionValue(itemIcon, "itemIcon");
        itemIcon.setImageResource(item.a);
        QTextView itemText = ((com.quizlet.quizletandroid.ui.common.databinding.e) e()).c;
        Intrinsics.checkNotNullExpressionValue(itemText, "itemText");
        Context context = this.b;
        Intrinsics.checkNotNullExpressionValue(context, "<get-context>(...)");
        com.quizlet.qutils.string.f fVar = item.b;
        fVar.getClass();
        itemText.setText(AbstractC3053s1.e(fVar, context));
        QuizletPlusBadge lockedBadge = ((com.quizlet.quizletandroid.ui.common.databinding.e) e()).d;
        Intrinsics.checkNotNullExpressionValue(lockedBadge, "lockedBadge");
        A0 a0 = A0.a;
        A0 a02 = item.c;
        lockedBadge.setVisibility(a02 == a0 ? 0 : 8);
        QTextView newLabel = ((com.quizlet.quizletandroid.ui.common.databinding.e) e()).e;
        Intrinsics.checkNotNullExpressionValue(newLabel, "newLabel");
        newLabel.setVisibility(a02 != A0.c ? 8 : 0);
    }
}
