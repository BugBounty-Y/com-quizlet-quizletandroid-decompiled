package com.quizlet.explanations.solution.recyclerview.step;

import android.content.Context;
import android.view.ViewGroup;
import androidx.compose.ui.platform.ComposeView;
import androidx.lifecycle.X;
import androidx.recyclerview.widget.AbstractC1358c;
import androidx.recyclerview.widget.F0;
import com.onetrust.otpublishers.headless.UI.adapter.s;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.R;
import com.quizlet.upgrade.data.v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class l extends com.quizlet.baserecyclerview.b {
    public final /* synthetic */ int c = 1;
    public final Object d;

    public l() {
        super((AbstractC1358c) AbstractC4178x.h("diffUtilCallback"));
        this.d = new X(1);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        switch (this.c) {
            case 0:
                k holder = (k) f0;
                Intrinsics.checkNotNullParameter(holder, "holder");
                e item = (e) d(i);
                Intrinsics.d(item);
                holder.getClass();
                Intrinsics.checkNotNullParameter(item, "item");
                holder.d.setContent(new androidx.compose.runtime.internal.d(true, -609560868, new j(holder, item, 1)));
                break;
            default:
                com.quizlet.upgrade.ui.featurelist.b holder2 = (com.quizlet.upgrade.ui.featurelist.b) f0;
                Intrinsics.checkNotNullParameter(holder2, "holder");
                v vVar = (v) d(i);
                Intrinsics.d(vVar);
                holder2.c(vVar);
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        switch (this.c) {
            case 0:
                Intrinsics.checkNotNullParameter(parent, "parent");
                Context context = parent.getContext();
                Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
                return new k(new ComposeView(context, null, 6), (com.quizlet.explanations.solution.viewmodel.b) this.d);
            default:
                Intrinsics.checkNotNullParameter(parent, "parent");
                return new com.quizlet.upgrade.ui.featurelist.b(com.quizlet.baserecyclerview.b.g(parent, R.layout.list_item_feature_footer), (X) this.d);
        }
    }

    public l(com.quizlet.explanations.solution.viewmodel.b renderListener) {
        Intrinsics.checkNotNullParameter(renderListener, "renderListener");
        s diffUtilCallback = new s(2);
        Intrinsics.checkNotNullParameter(diffUtilCallback, "diffUtilCallback");
        super((AbstractC1358c) diffUtilCallback);
        this.d = renderListener;
    }
}
