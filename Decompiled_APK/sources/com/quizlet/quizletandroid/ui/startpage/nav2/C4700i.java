package com.quizlet.quizletandroid.ui.startpage.nav2;

import android.content.Intent;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.quizletandroid.databinding.b0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4700i implements androidx.swiperefreshlayout.widget.j, InterfaceC1062t, com.quizlet.qutils.rx.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ OldHomeFragment b;

    public /* synthetic */ C4700i(OldHomeFragment oldHomeFragment, int i) {
        this.a = i;
        this.b = oldHomeFragment;
    }

    @Override // com.quizlet.qutils.rx.c
    public void accept(Object obj) {
        OldHomeFragment oldHomeFragment = this.b;
        switch (this.a) {
            case 2:
                Intent it2 = (Intent) obj;
                String str = OldHomeFragment.d1;
                Intrinsics.checkNotNullParameter(it2, "it");
                oldHomeFragment.startActivityForResult(it2, 201);
                break;
            default:
                io.reactivex.rxjava3.disposables.b it3 = (io.reactivex.rxjava3.disposables.b) obj;
                String str2 = OldHomeFragment.d1;
                Intrinsics.checkNotNullParameter(it3, "it");
                oldHomeFragment.I(it3);
                break;
        }
    }

    @Override // androidx.swiperefreshlayout.widget.j
    public void onRefresh() {
        String str = OldHomeFragment.d1;
        this.b.Y();
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) {
        String str = OldHomeFragment.d1;
        androidx.core.graphics.e eVarG = d0.a.g(647);
        Intrinsics.d(view);
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (layoutParams == null) {
            throw new NullPointerException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
        }
        ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
        marginLayoutParams.topMargin = eVarG.b;
        view.setLayoutParams(marginLayoutParams);
        RecyclerView unifiedRecyclerView = ((b0) this.b.J()).h;
        Intrinsics.checkNotNullExpressionValue(unifiedRecyclerView, "unifiedRecyclerView");
        unifiedRecyclerView.setPadding(eVarG.a, unifiedRecyclerView.getPaddingTop(), unifiedRecyclerView.getPaddingRight(), unifiedRecyclerView.getPaddingBottom());
        return D0.b;
    }
}
