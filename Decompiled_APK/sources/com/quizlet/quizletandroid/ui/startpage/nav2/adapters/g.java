package com.quizlet.quizletandroid.ui.startpage.nav2.adapters;

import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.F0;
import com.onetrust.otpublishers.headless.UI.adapter.s;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4717m;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4718n;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.G;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends a {
    public final /* synthetic */ int c;
    public final L d;
    public final Y e;

    public g(L l, Y studiableLoggingDelegate, int i) {
        this.c = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(studiableLoggingDelegate, "studiableLoggingDelegate");
                s diffUtilCallback = new s(2);
                Intrinsics.checkNotNullParameter(diffUtilCallback, "diffUtilCallback");
                super(diffUtilCallback);
                this.d = l;
                this.e = studiableLoggingDelegate;
                break;
            case 2:
                Intrinsics.checkNotNullParameter(studiableLoggingDelegate, "studiableLoggingDelegate");
                s diffUtilCallback2 = new s(2);
                Intrinsics.checkNotNullParameter(diffUtilCallback2, "diffUtilCallback");
                super(diffUtilCallback2);
                this.d = l;
                this.e = studiableLoggingDelegate;
                break;
            default:
                Intrinsics.checkNotNullParameter(studiableLoggingDelegate, "studiableLoggingDelegate");
                s diffUtilCallback3 = new s(2);
                Intrinsics.checkNotNullParameter(diffUtilCallback3, "diffUtilCallback");
                super(diffUtilCallback3);
                this.d = l;
                this.e = studiableLoggingDelegate;
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        switch (this.c) {
            case 0:
                com.quizlet.quizletandroid.ui.common.adapter.viewholder.f holder = (com.quizlet.quizletandroid.ui.common.adapter.viewholder.f) f0;
                Intrinsics.checkNotNullParameter(holder, "holder");
                C4718n c4718n = (C4718n) d(i);
                holder.c(c4718n.d);
                holder.itemView.setTag(R.id.unifiedRecyclerView, Boolean.valueOf(c4718n.a));
                break;
            case 1:
                com.quizlet.quizletandroid.ui.common.adapter.viewholder.d holder2 = (com.quizlet.quizletandroid.ui.common.adapter.viewholder.d) f0;
                Intrinsics.checkNotNullParameter(holder2, "holder");
                C4717m c4717m = (C4717m) d(i);
                holder2.c(c4717m.d);
                holder2.itemView.setTag(R.id.unifiedRecyclerView, Boolean.valueOf(c4717m.a));
                break;
            default:
                com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.s holder3 = (com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.s) f0;
                Intrinsics.checkNotNullParameter(holder3, "holder");
                G g = (G) d(i);
                holder3.c(g.d);
                holder3.itemView.setTag(R.id.unifiedRecyclerView, Boolean.valueOf(g.a));
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        switch (this.c) {
            case 0:
                Intrinsics.checkNotNullParameter(parent, "parent");
                int i2 = com.quizlet.quizletandroid.ui.common.adapter.viewholder.f.e;
                View viewG = com.quizlet.baserecyclerview.b.g(parent, R.layout.nav2_listitem_new_group);
                a.h(viewG);
                return new com.quizlet.quizletandroid.ui.common.adapter.viewholder.f(viewG, new com.quizlet.features.settings.composables.dialogs.a(this, 9));
            case 1:
                Intrinsics.checkNotNullParameter(parent, "parent");
                int i3 = com.quizlet.quizletandroid.ui.common.adapter.viewholder.d.e;
                View viewG2 = com.quizlet.baserecyclerview.b.g(parent, R.layout.nav2_listitem_new_folder);
                a.h(viewG2);
                return new com.quizlet.quizletandroid.ui.common.adapter.viewholder.d(viewG2, new com.quizlet.quizletandroid.ui.common.ads.G(this, 17));
            default:
                Intrinsics.checkNotNullParameter(parent, "parent");
                int i4 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.s.e;
                View viewG3 = com.quizlet.baserecyclerview.b.g(parent, R.layout.nav2_listitem_note);
                a.h(viewG3);
                return new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.s(viewG3, new com.quizlet.quizletandroid.ui.common.ads.G(this, 18));
        }
    }
}
