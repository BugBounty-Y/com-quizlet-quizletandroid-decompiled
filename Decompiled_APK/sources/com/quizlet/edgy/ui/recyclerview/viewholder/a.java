package com.quizlet.edgy.ui.recyclerview.viewholder;

import android.content.Context;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.measurement.AbstractC3058t1;
import com.quizlet.edgy.ui.fragment.C4192f;
import com.quizlet.quizletandroid.R;
import java.util.Arrays;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends com.quizlet.baserecyclerview.c {
    public final C4192f d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(ConstraintLayout view, C4192f onClicked) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(onClicked, "onClicked");
        this.d = onClicked;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        com.quizlet.edgy.databinding.d dVarA = com.quizlet.edgy.databinding.d.a(this.a);
        Intrinsics.checkNotNullExpressionValue(dVarA, "bind(...)");
        return dVarA;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(Unit item) {
        String string;
        Intrinsics.checkNotNullParameter(item, "item");
        com.quizlet.edgy.databinding.d dVar = (com.quizlet.edgy.databinding.d) e();
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        List listP = C4933y.P(args);
        Context context = this.b;
        Intrinsics.checkNotNullExpressionValue(context, "<get-context>(...)");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        if (listP == null || listP.isEmpty()) {
            string = context.getString(R.string.edgy_flow_add_new_course);
            Intrinsics.d(string);
        } else {
            Object[] array = AbstractC3058t1.b(context, listP).toArray(new Object[0]);
            string = context.getString(R.string.edgy_flow_add_new_course, Arrays.copyOf(array, array.length));
            Intrinsics.d(string);
        }
        dVar.b.setText(string.toString());
        dVar.b.setOnClickListener(new com.braze.ui.inappmessage.d(this, 15));
    }
}
