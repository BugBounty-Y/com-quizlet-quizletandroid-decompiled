package com.quizlet.features.infra.legacyadapter.viewholder;

import android.view.View;
import android.widget.ImageView;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.features.infra.legacyadapter.common.ListitemPressIndicatorLine;
import com.quizlet.features.infra.legacyadapter.common.UserListTitleView;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends com.quizlet.baserecyclerview.c implements i {
    public static final /* synthetic */ int f = 0;
    public final com.quizlet.infra.legacysyncengine.managers.d d;
    public io.reactivex.rxjava3.internal.observers.h e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(View itemView) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        this.d = (com.quizlet.infra.legacysyncengine.managers.d) ((u) ((com.quizlet.features.infra.legacyadapter.di.a) K6.b(com.quizlet.features.infra.legacyadapter.di.a.class, itemView.getContext().getApplicationContext()))).Z.get();
    }

    @Override // com.quizlet.features.infra.legacyadapter.viewholder.i
    public final void a(View.OnClickListener listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        io.reactivex.rxjava3.internal.observers.h hVar = this.e;
        if (hVar != null) {
            io.reactivex.rxjava3.internal.disposables.a.a(hVar);
        }
        View itemView = this.itemView;
        Intrinsics.checkNotNullExpressionValue(itemView, "itemView");
        this.e = (io.reactivex.rxjava3.internal.observers.h) com.facebook.appevents.m.o(itemView).u(new d(listener, 0), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
    }

    @Override // com.quizlet.features.infra.legacyadapter.viewholder.i
    public final void b(View.OnLongClickListener onLongClickListener) {
        this.itemView.setOnLongClickListener(onLongClickListener);
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        Void item = (Void) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.itemView;
        CardView cardView = (CardView) view;
        int i = R.id.listitem_folder_card_layout;
        ConstraintLayout constraintLayout = (ConstraintLayout) AbstractC3375o2.c(R.id.listitem_folder_card_layout, view);
        if (constraintLayout != null) {
            i = R.id.listitem_folder_icon;
            if (((ImageView) AbstractC3375o2.c(R.id.listitem_folder_icon, view)) != null) {
                i = R.id.listitem_folder_name;
                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.listitem_folder_name, view);
                if (qTextView != null) {
                    i = R.id.listitemPressIndicatorLine;
                    if (((ListitemPressIndicatorLine) AbstractC3375o2.c(R.id.listitemPressIndicatorLine, view)) != null) {
                        i = R.id.userTitleView;
                        UserListTitleView userListTitleView = (UserListTitleView) AbstractC3375o2.c(R.id.userTitleView, view);
                        if (userListTitleView != null) {
                            com.quizlet.features.infra.legacyadapter.databinding.e eVar = new com.quizlet.features.infra.legacyadapter.databinding.e(cardView, constraintLayout, qTextView, userListTitleView);
                            Intrinsics.checkNotNullExpressionValue(eVar, "bind(...)");
                            return eVar;
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    public final void f(String folderName, String creatorUsername, int i, String str, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(folderName, "folderName");
        Intrinsics.checkNotNullParameter(creatorUsername, "creatorUsername");
        ((com.quizlet.features.infra.legacyadapter.databinding.e) e()).c.setText(folderName);
        ((com.quizlet.features.infra.legacyadapter.databinding.e) e()).d.a(str, i, creatorUsername, z);
        UserListTitleView userTitleView = ((com.quizlet.features.infra.legacyadapter.databinding.e) e()).d;
        Intrinsics.checkNotNullExpressionValue(userTitleView, "userTitleView");
        userTitleView.setVisibility(0);
        ((com.quizlet.features.infra.legacyadapter.databinding.e) e()).b.setBackgroundResource(z2 ? R.drawable.accent_rectangle_border : 0);
    }

    public final void g(String folderName, boolean z) {
        Intrinsics.checkNotNullParameter(folderName, "folderName");
        ((com.quizlet.features.infra.legacyadapter.databinding.e) e()).c.setText(folderName);
        UserListTitleView userTitleView = ((com.quizlet.features.infra.legacyadapter.databinding.e) e()).d;
        Intrinsics.checkNotNullExpressionValue(userTitleView, "userTitleView");
        userTitleView.setVisibility(8);
        ((com.quizlet.features.infra.legacyadapter.databinding.e) e()).b.setBackgroundResource(z ? R.drawable.accent_rectangle_border : 0);
    }

    public final com.quizlet.infra.legacysyncengine.managers.d h() {
        com.quizlet.infra.legacysyncengine.managers.d dVar = this.d;
        if (dVar != null) {
            return dVar;
        }
        Intrinsics.m("loggedInUserManager");
        throw null;
    }
}
