package com.quizlet.edgy.ui.recyclerview.viewholder;

import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.edgy.ui.fragment.C4196j;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends com.quizlet.baserecyclerview.c {
    public final C4196j d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(ConstraintLayout view, C4196j onCourseRemove) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(onCourseRemove, "onCourseRemove");
        this.d = onCourseRemove;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        com.quizlet.edgy.databinding.f fVarA = com.quizlet.edgy.databinding.f.a(this.a);
        Intrinsics.checkNotNullExpressionValue(fVarA, "bind(...)");
        return fVarA;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(com.quizlet.edgy.ui.recyclerview.adapter.d item) {
        Intrinsics.checkNotNullParameter(item, "item");
        com.quizlet.edgy.databinding.f fVar = (com.quizlet.edgy.databinding.f) e();
        fVar.b.setOnClickListener(new com.braze.ui.inappmessage.views.a(16, this, item));
        String str = item.b;
        TextView textView = fVar.d;
        String str2 = item.c;
        if (str == null || str.length() == 0) {
            textView.setText(str2);
            g(true);
            return;
        }
        int length = str2.length();
        String str3 = item.b;
        if (length == 0) {
            textView.setText(str3);
            g(true);
        } else {
            fVar.c.setText(str3);
            fVar.e.setText(str2);
            g(false);
        }
    }

    public final void g(boolean z) {
        com.quizlet.edgy.databinding.f fVar = (com.quizlet.edgy.databinding.f) e();
        TextView courseCodeOrName = fVar.d;
        Intrinsics.checkNotNullExpressionValue(courseCodeOrName, "courseCodeOrName");
        courseCodeOrName.setVisibility(z ? 0 : 8);
        TextView courseCode = fVar.c;
        Intrinsics.checkNotNullExpressionValue(courseCode, "courseCode");
        courseCode.setVisibility(!z ? 0 : 8);
        TextView courseName = fVar.e;
        Intrinsics.checkNotNullExpressionValue(courseName, "courseName");
        courseName.setVisibility(z ? 8 : 0);
    }
}
