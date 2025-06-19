package com.quizlet.edgy.ui.recyclerview.viewholder;

import android.content.Context;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.quizlet.edgy.databinding.h;
import com.quizlet.edgy.ui.fragment.C4196j;
import com.quizlet.edgy.ui.recyclerview.adapter.i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f extends com.quizlet.baserecyclerview.c {
    public final C4196j d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(ConstraintLayout view, C4196j onSchoolSelected) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(onSchoolSelected, "onSchoolSelected");
        this.d = onSchoolSelected;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        h hVarA = h.a(this.a);
        Intrinsics.checkNotNullExpressionValue(hVarA, "bind(...)");
        return hVarA;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(i item) {
        Intrinsics.checkNotNullParameter(item, "item");
        h hVar = (h) e();
        hVar.c.setText(item.b);
        Context context = this.b;
        Intrinsics.checkNotNullExpressionValue(context, "<get-context>(...)");
        com.quizlet.qutils.string.f fVar = item.f;
        fVar.getClass();
        hVar.b.setText(AbstractC3053s1.e(fVar, context));
        hVar.a.setOnClickListener(new com.braze.ui.inappmessage.views.a(18, this, item));
    }
}
