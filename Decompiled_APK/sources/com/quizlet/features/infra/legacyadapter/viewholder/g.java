package com.quizlet.features.infra.legacyadapter.viewholder;

import android.view.View;
import android.widget.ImageView;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.features.infra.legacyadapter.common.ListitemPressIndicatorLine;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends F0 implements i {
    public static final /* synthetic */ int b = 0;
    public final com.quizlet.features.infra.legacyadapter.databinding.f a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(View itemView) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        int i = R.id.listitem_group_card_layout;
        ConstraintLayout constraintLayout = (ConstraintLayout) AbstractC3375o2.c(R.id.listitem_group_card_layout, itemView);
        if (constraintLayout != null) {
            i = R.id.listitem_group_detail_school;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.listitem_group_detail_school, itemView);
            if (qTextView != null) {
                i = R.id.listitem_group_icon;
                if (((ImageView) AbstractC3375o2.c(R.id.listitem_group_icon, itemView)) != null) {
                    i = R.id.listitem_group_name;
                    QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.listitem_group_name, itemView);
                    if (qTextView2 != null) {
                        i = R.id.listitemPressIndicatorLine;
                        if (((ListitemPressIndicatorLine) AbstractC3375o2.c(R.id.listitemPressIndicatorLine, itemView)) != null) {
                            com.quizlet.features.infra.legacyadapter.databinding.f fVar = new com.quizlet.features.infra.legacyadapter.databinding.f((CardView) itemView, constraintLayout, qTextView, qTextView2, 0);
                            Intrinsics.checkNotNullExpressionValue(fVar, "bind(...)");
                            this.a = fVar;
                            return;
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(itemView.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.features.infra.legacyadapter.viewholder.i
    public final void a(View.OnClickListener listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        View itemView = this.itemView;
        Intrinsics.checkNotNullExpressionValue(itemView, "itemView");
        com.facebook.appevents.m.o(itemView).u(new f((com.quizlet.features.infra.legacyadapter.a) listener, 0), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
    }

    @Override // com.quizlet.features.infra.legacyadapter.viewholder.i
    public final void b(View.OnLongClickListener listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.itemView.setOnLongClickListener(listener);
    }
}
