package com.quizlet.quizletandroid.ui.joincontenttofolder;

import android.view.View;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.F0;
import com.quizlet.features.infra.legacyadapter.common.UserListTitleView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l extends F0 {
    public final TextView a;
    public final ConstraintLayout b;
    public final UserListTitleView c;
    public com.quizlet.quizletandroid.ui.joincontenttofolder.models.b d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(m mVar, View itemView) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        View viewFindViewById = itemView.findViewById(R.id.listitem_folder_name);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById, "findViewById(...)");
        this.a = (TextView) viewFindViewById;
        View viewFindViewById2 = itemView.findViewById(R.id.listitem_folder_card_layout);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById2, "findViewById(...)");
        this.b = (ConstraintLayout) viewFindViewById2;
        View viewFindViewById3 = itemView.findViewById(R.id.userTitleView);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById3, "findViewById(...)");
        this.c = (UserListTitleView) viewFindViewById3;
        com.facebook.appevents.m.o(itemView).u(new com.quizlet.billing.manager.b(12, mVar, this), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
    }
}
