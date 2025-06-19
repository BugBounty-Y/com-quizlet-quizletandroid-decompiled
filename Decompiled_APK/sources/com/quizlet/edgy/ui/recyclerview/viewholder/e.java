package com.quizlet.edgy.ui.recyclerview.viewholder;

import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.edgy.databinding.g;
import com.quizlet.edgy.ui.fragment.C4196j;
import com.quizlet.quizletandroid.R;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e extends com.quizlet.baserecyclerview.c {
    public final C4196j d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(ConstraintLayout view, C4196j onCourseSelected) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(onCourseSelected, "onCourseSelected");
        this.d = onCourseSelected;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        g gVarA = g.a(this.a);
        Intrinsics.checkNotNullExpressionValue(gVarA, "bind(...)");
        return gVarA;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v5, types: [java.lang.CharSequence] */
    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(com.quizlet.edgy.ui.recyclerview.adapter.g item) {
        String upperCase;
        Intrinsics.checkNotNullParameter(item, "item");
        g gVar = (g) e();
        TextView textView = gVar.b;
        if (item.c.length() == 0) {
            String string = this.b.getString(R.string.edgy_flow_course);
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            upperCase = string.toUpperCase(Locale.ROOT);
            Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
        } else {
            upperCase = item.c;
        }
        textView.setText(upperCase);
        String str = item.b;
        int length = str.length();
        String text = str;
        if (length == 0) {
            text = gVar.b.getText();
        }
        gVar.c.setText(text);
        gVar.a.setOnClickListener(new com.braze.ui.inappmessage.views.a(17, this, item));
    }
}
