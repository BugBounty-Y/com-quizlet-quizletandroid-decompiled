package com.quizlet.explanations.textbook.chaptermenu.recyclerview;

import android.content.Context;
import android.view.View;
import com.quizlet.explanations.databinding.q;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes2.dex */
public final class h extends b {
    public final u d;
    public final u e;
    public final u f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(View view) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        final int i = 0;
        this.d = l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.chaptermenu.recyclerview.g
            public final /* synthetic */ h b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                    case 0:
                        QTextView chapterMenuItemText = ((q) this.b.e()).c;
                        Intrinsics.checkNotNullExpressionValue(chapterMenuItemText, "chapterMenuItemText");
                        return chapterMenuItemText;
                    case 1:
                        return ((q) this.b.e()).b;
                    default:
                        return ((q) this.b.e()).d;
                }
            }
        });
        final int i2 = 1;
        this.e = l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.chaptermenu.recyclerview.g
            public final /* synthetic */ h b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        QTextView chapterMenuItemText = ((q) this.b.e()).c;
                        Intrinsics.checkNotNullExpressionValue(chapterMenuItemText, "chapterMenuItemText");
                        return chapterMenuItemText;
                    case 1:
                        return ((q) this.b.e()).b;
                    default:
                        return ((q) this.b.e()).d;
                }
            }
        });
        final int i3 = 2;
        this.f = l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.chaptermenu.recyclerview.g
            public final /* synthetic */ h b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i3) {
                    case 0:
                        QTextView chapterMenuItemText = ((q) this.b.e()).c;
                        Intrinsics.checkNotNullExpressionValue(chapterMenuItemText, "chapterMenuItemText");
                        return chapterMenuItemText;
                    case 1:
                        return ((q) this.b.e()).b;
                    default:
                        return ((q) this.b.e()).d;
                }
            }
        });
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        q qVarA = q.a(this.a);
        Intrinsics.checkNotNullExpressionValue(qVarA, "bind(...)");
        return qVarA;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(c item) {
        Intrinsics.checkNotNullParameter(item, "item");
        Context context = this.b;
        String string = context.getResources().getString(R.string.exercise_name, item.c);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        QTextView qTextView = (QTextView) this.d.getValue();
        Intrinsics.checkNotNullExpressionValue(context, "<get-context>(...)");
        int iA = com.quizlet.themes.extensions.a.a(context, R.attr.textColorDisabled);
        boolean z = item.d;
        qTextView.setText(com.quizlet.features.notes.upload.navigation.c.b(string, iA, null, z));
        Object value = this.e.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((View) value).setVisibility(8);
        Object value2 = this.f.getValue();
        Intrinsics.checkNotNullExpressionValue(value2, "getValue(...)");
        ((View) value2).setVisibility(z ? 8 : 0);
        if (item.b != null) {
            if ((item.a() ? item.b() : null) != null) {
                this.itemView.setOnClickListener(new com.braze.ui.inappmessage.d(item, 22));
            }
        }
    }
}
