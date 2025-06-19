package com.quizlet.explanations.textbook.chaptermenu.recyclerview;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import com.quizlet.explanations.databinding.q;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes2.dex */
public final class k extends b {
    public final u d;
    public final u e;
    public final u f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(View view) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        final int i = 0;
        this.d = l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.chaptermenu.recyclerview.j
            public final /* synthetic */ k b;

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
                        return ((q) this.b.e()).d;
                    default:
                        ImageView chapterMenuItemChevron = ((q) this.b.e()).b;
                        Intrinsics.checkNotNullExpressionValue(chapterMenuItemChevron, "chapterMenuItemChevron");
                        return chapterMenuItemChevron;
                }
            }
        });
        final int i2 = 1;
        this.e = l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.chaptermenu.recyclerview.j
            public final /* synthetic */ k b;

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
                        return ((q) this.b.e()).d;
                    default:
                        ImageView chapterMenuItemChevron = ((q) this.b.e()).b;
                        Intrinsics.checkNotNullExpressionValue(chapterMenuItemChevron, "chapterMenuItemChevron");
                        return chapterMenuItemChevron;
                }
            }
        });
        final int i3 = 2;
        this.f = l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.chaptermenu.recyclerview.j
            public final /* synthetic */ k b;

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
                        return ((q) this.b.e()).d;
                    default:
                        ImageView chapterMenuItemChevron = ((q) this.b.e()).b;
                        Intrinsics.checkNotNullExpressionValue(chapterMenuItemChevron, "chapterMenuItemChevron");
                        return chapterMenuItemChevron;
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
    public final void c(i item) {
        Intrinsics.checkNotNullParameter(item, "item");
        Object[] objArr = {item.c};
        Context context = this.b;
        String string = context.getString(R.string.section_row_title_name_part, objArr);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        String string2 = context.getString(R.string.section_row_title, string, item.b);
        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
        QTextView qTextView = (QTextView) this.d.getValue();
        Intrinsics.checkNotNullExpressionValue(context, "<get-context>(...)");
        int iA = com.quizlet.themes.extensions.a.a(context, R.attr.textColorDisabled);
        boolean z = item.e;
        qTextView.setText(com.quizlet.features.notes.upload.navigation.c.b(string2, iA, string, z));
        Object value = this.e.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((View) value).setVisibility(!z ? 0 : 8);
        ((ImageView) this.f.getValue()).setVisibility(z ? 0 : 8);
        this.itemView.setOnClickListener(new com.braze.ui.inappmessage.d(item, 23));
    }
}
