package com.quizlet.explanations.solution.recyclerview.tablayout;

import android.content.Context;
import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.tabs.g;
import com.google.android.material.tabs.k;
import com.quizlet.explanations.databinding.v;
import com.quizlet.partskit.widgets.QTabLayout;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.i;
import kotlin.ranges.l;

/* loaded from: classes2.dex */
public final class c extends com.quizlet.baserecyclerview.c {
    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.itemView;
        QTabLayout qTabLayout = (QTabLayout) AbstractC3375o2.c(R.id.tabLayout, view);
        if (qTabLayout == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.tabLayout)));
        }
        v vVar = new v((ConstraintLayout) view, qTabLayout);
        Intrinsics.checkNotNullExpressionValue(vVar, "bind(...)");
        return vVar;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(b item) {
        Intrinsics.checkNotNullParameter(item, "item");
        QTabLayout qTabLayout = ((v) e()).b;
        ArrayList arrayList = qTabLayout.L;
        arrayList.clear();
        qTabLayout.l();
        i it2 = l.h(0, item.a).iterator();
        while (it2.c) {
            int iNextInt = it2.nextInt();
            g gVarJ = qTabLayout.j();
            gVarJ.a = Integer.valueOf(iNextInt);
            com.quizlet.qutils.string.a aVar = new com.quizlet.qutils.string.a(iNextInt);
            Context context = qTabLayout.getContext();
            Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
            gVarJ.a(AbstractC3053s1.e(aVar, context));
            Intrinsics.checkNotNullExpressionValue(gVarJ, "apply(...)");
            qTabLayout.a(gVarJ);
        }
        qTabLayout.m(qTabLayout.i(item.c), true);
        k kVar = new k(item, 1);
        if (arrayList.contains(kVar)) {
            return;
        }
        arrayList.add(kVar);
    }
}
