package com.quizlet.quizletandroid.ui.joincontenttofolder;

import android.view.LayoutInflater;
import android.view.ViewGroup;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.V;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.UI.adapter.s;
import com.quizlet.features.infra.legacyadapter.common.UserListTitleView;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends V {
    public static final s e = new s(5);
    public final com.quizlet.quizletandroid.ui.globalnav.composable.s c;
    public final com.quizlet.quizletandroid.ui.common.adapter.viewholder.h d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(com.quizlet.quizletandroid.ui.globalnav.composable.s folderClickListener, com.quizlet.quizletandroid.ui.common.adapter.viewholder.h addFolderClickListener) {
        super(e);
        Intrinsics.checkNotNullParameter(folderClickListener, "folderClickListener");
        Intrinsics.checkNotNullParameter(addFolderClickListener, "addFolderClickListener");
        this.c = folderClickListener;
        this.d = addFolderClickListener;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        return i == 0 ? 1 : 2;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 holder, int i) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        if (i == 0) {
            com.quizlet.features.infra.legacyadapter.viewholder.l lVar = (com.quizlet.features.infra.legacyadapter.viewholder.l) holder;
            Object objD = d(i);
            Intrinsics.e(objD, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.joincontenttofolder.models.AddFolderBottomItem");
            lVar.getClass();
            com.quizlet.quizletandroid.ui.common.adapter.viewholder.h clickListener = this.d;
            Intrinsics.checkNotNullParameter(clickListener, "clickListener");
            QButton topButton = ((com.quizlet.features.infra.legacyadapter.databinding.c) lVar.e()).b;
            Intrinsics.checkNotNullExpressionValue(topButton, "topButton");
            topButton.setText(R.string.add_set_create_new_folder);
            topButton.setOnClickListener(clickListener);
            return;
        }
        l lVar2 = (l) holder;
        Object objD2 = d(i);
        Intrinsics.e(objD2, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.joincontenttofolder.models.FolderItem");
        com.quizlet.quizletandroid.ui.joincontenttofolder.models.b folderItem = (com.quizlet.quizletandroid.ui.joincontenttofolder.models.b) objD2;
        lVar2.getClass();
        Intrinsics.checkNotNullParameter(folderItem, "folderItem");
        lVar2.d = folderItem;
        lVar2.a.setText(folderItem.a.g());
        UserListTitleView userListTitleView = lVar2.c;
        com.quizlet.quizletandroid.ui.joincontenttofolder.models.d dVar = folderItem.b;
        if (dVar == null) {
            userListTitleView.setVisibility(8);
        } else {
            userListTitleView.a(dVar.a, dVar.c, dVar.b, dVar.d);
            userListTitleView.setVisibility(0);
        }
        lVar2.b.setBackgroundResource(folderItem.c ? R.drawable.accent_rectangle_border : 0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        if (i != 1) {
            return new l(this, Z.c(parent, R.layout.nav2_listitem_folder, parent, false));
        }
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(parent.getContext());
        int i2 = com.quizlet.features.infra.legacyadapter.viewholder.l.d;
        return new com.quizlet.features.infra.legacyadapter.viewholder.l(layoutInflaterFrom.inflate(R.layout.listitem_top_button, parent, false));
    }
}
