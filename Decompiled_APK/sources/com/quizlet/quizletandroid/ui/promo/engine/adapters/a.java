package com.quizlet.quizletandroid.ui.promo.engine.adapters;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.promo.rateus.e;
import com.quizlet.quizletandroid.ui.startpage.nav2.OldHomeFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.K;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.completable.f;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public static final a a = new a();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        com.quizlet.quizletandroid.ui.promo.rateus.a aVar;
        Pair pair = (Pair) obj;
        Intrinsics.checkNotNullParameter(pair, "<destruct>");
        com.quizlet.quizletandroid.ui.promo.rateus.b bVar = (com.quizlet.quizletandroid.ui.promo.rateus.b) pair.a;
        Object obj2 = pair.b;
        Intrinsics.checkNotNullExpressionValue(obj2, "component2(...)");
        if (((Boolean) obj2).booleanValue() && (aVar = (com.quizlet.quizletandroid.ui.promo.rateus.a) bVar.e.get()) != null) {
            OldHomeFragment oldHomeFragment = (OldHomeFragment) aVar;
            RecyclerView recyclerViewX = oldHomeFragment.X();
            LayoutInflater layoutInflaterFrom = LayoutInflater.from(recyclerViewX.getContext());
            int i = e.g;
            View view = new e(layoutInflaterFrom.inflate(R.layout.view_rateus_promo, (ViewGroup) recyclerViewX, false), bVar, bVar.b).a;
            Intrinsics.checkNotNullParameter(view, "view");
            Y y = oldHomeFragment.t;
            if (y == null) {
                Intrinsics.m("viewModel");
                throw null;
            }
            Intrinsics.checkNotNullParameter(view, "view");
            y.w1 = new K(view);
            oldHomeFragment.a0(true);
        }
        return f.a;
    }
}
