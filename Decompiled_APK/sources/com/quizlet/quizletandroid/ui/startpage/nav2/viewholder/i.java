package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import android.content.Context;
import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.T;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.Q;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import java.util.List;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int d = 0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(View itemView) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        List item = (List) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.horizontalHomeRecyclerView, view);
        if (recyclerView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.horizontalHomeRecyclerView)));
        }
        Q q = new Q((ConstraintLayout) view, recyclerView);
        Intrinsics.checkNotNullExpressionValue(q, "bind(...)");
        return q;
    }

    public final void f(com.quizlet.quizletandroid.ui.startpage.nav2.model.u homeSectionType, Y homeScrollDelegate, int i, Function1 setUpAdapterFunction) {
        Intrinsics.checkNotNullParameter(homeSectionType, "homeSectionType");
        Intrinsics.checkNotNullParameter(homeScrollDelegate, "homeScrollDelegate");
        Intrinsics.checkNotNullParameter(setUpAdapterFunction, "setUpAdapterFunction");
        RecyclerView recyclerView = ((Q) e()).b;
        Intrinsics.checkNotNullExpressionValue(recyclerView, "horizontalHomeRecyclerView");
        Context context = this.itemView.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        Intrinsics.checkNotNullParameter(context, "context");
        AbstractC1381n0 layoutManager = recyclerView.getLayoutManager();
        Intrinsics.e(layoutManager, "null cannot be cast to non-null type androidx.recyclerview.widget.LinearLayoutManager");
        ((LinearLayoutManager) layoutManager).k1(0);
        recyclerView.setPaddingRelative((int) context.getResources().getDimension(R.dimen.home_horizontal_scroll_start_recycler_padding), 0, (int) context.getResources().getDimension(R.dimen.home_horizontal_scroll_end_recycler_padding), 0);
        recyclerView.setClipToPadding(false);
        if (recyclerView.getOnFlingListener() == null) {
            new T(0).a(recyclerView);
        }
        setUpAdapterFunction.invoke(recyclerView);
        io.reactivex.rxjava3.disposables.b disposable = new com.jakewharton.rxbinding4.recyclerview.c(recyclerView, 1).l(g.a).u(new h(recyclerView, homeScrollDelegate, homeSectionType, i), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
        Intrinsics.checkNotNullExpressionValue(disposable, "subscribe(...)");
        homeScrollDelegate.getClass();
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        homeScrollDelegate.x1.b(disposable);
    }
}
