package com.quizlet.explanations.textbook.tableofcontents.recyclerview;

import android.content.Context;
import android.view.View;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.AssemblyPill;
import com.quizlet.explanations.databinding.p;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.text.StringsKt;
import kotlin.u;

/* loaded from: classes2.dex */
public final class f extends com.quizlet.baserecyclerview.c {
    public final u d;
    public final u e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(View view) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        final int i = 0;
        this.d = l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.tableofcontents.recyclerview.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                    case 0:
                        return ((p) this.b.e()).b;
                    default:
                        AssemblyPill comingSoonBadge = ((p) this.b.e()).c;
                        Intrinsics.checkNotNullExpressionValue(comingSoonBadge, "comingSoonBadge");
                        return comingSoonBadge;
                }
            }
        });
        final int i2 = 1;
        this.e = l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.tableofcontents.recyclerview.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        return ((p) this.b.e()).b;
                    default:
                        AssemblyPill comingSoonBadge = ((p) this.b.e()).c;
                        Intrinsics.checkNotNullExpressionValue(comingSoonBadge, "comingSoonBadge");
                        return comingSoonBadge;
                }
            }
        });
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        int i = R.id.chapterText;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.chapterText, view);
        if (qTextView != null) {
            i = R.id.comingSoonBadge;
            AssemblyPill assemblyPill = (AssemblyPill) AbstractC3375o2.c(R.id.comingSoonBadge, view);
            if (assemblyPill != null) {
                p pVar = new p((CardView) view, qTextView, assemblyPill);
                Intrinsics.checkNotNullExpressionValue(pVar, "bind(...)");
                return pVar;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(d item) {
        Intrinsics.checkNotNullParameter(item, "item");
        Object value = this.d.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        boolean z = item.d;
        StringBuilder sb = new StringBuilder();
        String str = item.b;
        sb.append(str);
        sb.append(" ");
        sb.append(item.c);
        String string = StringsKt.g0(sb.toString()).toString();
        Context context = this.b;
        Intrinsics.checkNotNullExpressionValue(context, "<get-context>(...)");
        ((TextView) value).setText(com.quizlet.features.notes.upload.navigation.c.b(string, com.quizlet.themes.extensions.a.a(context, R.attr.textColorDisabled), str, z));
        ((AssemblyPill) this.e.getValue()).setVisibility(!item.d ? 0 : 8);
        this.itemView.setOnClickListener(new com.braze.ui.inappmessage.d(item, 25));
    }
}
