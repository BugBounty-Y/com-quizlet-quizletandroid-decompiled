package com.quizlet.features.infra.legacyadapter.viewholder;

import android.view.View;
import android.widget.LinearLayout;
import androidx.cardview.widget.CardView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.infra.legacyadapter.common.UserListTitleView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends com.quizlet.baserecyclerview.c implements i {
    public static final /* synthetic */ int d = 0;

    @Override // com.quizlet.features.infra.legacyadapter.viewholder.i
    public final void a(View.OnClickListener listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        View itemView = this.itemView;
        Intrinsics.checkNotNullExpressionValue(itemView, "itemView");
        com.facebook.appevents.m.o(itemView).u(new f((com.quizlet.features.infra.legacyadapter.a) listener, 1), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
    }

    @Override // com.quizlet.features.infra.legacyadapter.viewholder.i
    public final void b(View.OnLongClickListener listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.itemView.setOnLongClickListener(listener);
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        DBUser item = (DBUser) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        int i = R.id.listitem_user_card;
        if (((LinearLayout) AbstractC3375o2.c(R.id.listitem_user_card, view)) != null) {
            i = R.id.user_details_list_item;
            UserListTitleView userListTitleView = (UserListTitleView) AbstractC3375o2.c(R.id.user_details_list_item, view);
            if (userListTitleView != null) {
                com.quizlet.features.infra.legacyadapter.databinding.d dVar = new com.quizlet.features.infra.legacyadapter.databinding.d((CardView) view, userListTitleView);
                Intrinsics.checkNotNullExpressionValue(dVar, "bind(...)");
                return dVar;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }
}
