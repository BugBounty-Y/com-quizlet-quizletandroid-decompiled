package com.quizlet.quizletandroid.ui.common.adapter.ndl;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.V;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6;
import com.onetrust.otpublishers.headless.UI.adapter.s;
import com.quizlet.data.model.CreatedFolder;
import com.quizlet.data.model.CreatedFolderWithCreator;
import com.quizlet.data.model.User;
import com.quizlet.features.infra.legacyadapter.viewholder.e;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends V {
    public static final s d = new s(3);
    public final com.quizlet.data.interactor.course.a c;

    public b(com.quizlet.data.interactor.course.a aVar) {
        super(d);
        this.c = aVar;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        e holder = (e) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        CreatedFolderWithCreator createdFolderWithCreator = (CreatedFolderWithCreator) d(i);
        CreatedFolder createdFolder = createdFolderWithCreator.a;
        User user = createdFolderWithCreator.b;
        if (user == null) {
            holder.g(createdFolder.g(), false);
        } else {
            holder.f(createdFolder.g(), user.b, AbstractC3179j6.b(user), user.i, user.e, false);
        }
        com.quizlet.data.interactor.course.a aVar = this.c;
        if (aVar != null) {
            holder.a(new com.braze.ui.inappmessage.views.a(aVar, i, createdFolderWithCreator));
            holder.b(new a(aVar, i, createdFolderWithCreator));
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(parent.getContext());
        int i2 = e.f;
        View viewInflate = layoutInflaterFrom.inflate(R.layout.nav2_listitem_folder, parent, false);
        Intrinsics.d(viewInflate);
        return new e(viewInflate);
    }
}
