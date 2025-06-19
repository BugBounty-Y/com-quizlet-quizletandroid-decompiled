package com.quizlet.upgrade.ui.featurelist;

import android.content.Context;
import android.view.View;
import android.widget.TextView;
import androidx.lifecycle.Y;
import com.quizlet.baserecyclerview.c;
import com.quizlet.quizletandroid.R;
import com.quizlet.qutils.string.g;
import com.quizlet.uicommon.ui.common.text.d;
import com.quizlet.upgrade.data.s;
import com.quizlet.upgrade.data.v;
import com.quizlet.upgrade.databinding.e;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends c {
    public final Y d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(View view, Y footerItemClickEvent) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(footerItemClickEvent, "footerItemClickEvent");
        this.d = footerItemClickEvent;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        if (view == null) {
            throw new NullPointerException("rootView");
        }
        TextView textView = (TextView) view;
        e eVar = new e(textView, textView);
        Intrinsics.checkNotNullExpressionValue(eVar, "bind(...)");
        return eVar;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(v item) {
        Intrinsics.checkNotNullParameter(item, "item");
        TextView textView = ((e) e()).b;
        g gVarA = item.a();
        Context context = textView.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        textView.setText(gVarA.c(context));
        if (item.a) {
            textView.setTextAppearance(R.style.SubHeader_S4);
            textView.setTextColor(textView.getContext().getColorStateList(R.color.assembly_link_text_selector));
            textView.setOnClickListener(new com.braze.ui.inappmessage.views.a(29, this, item));
        } else {
            textView.setTextAppearance(R.style.Body_B4);
            Context context2 = textView.getContext();
            Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
            textView.setTextColor(com.quizlet.themes.extensions.a.a(context2, R.attr.AssemblyInfoText));
            textView.setOnClickListener(null);
        }
        if (item instanceof s) {
            textView.setMovementMethod((d) d.b.getValue());
        }
    }
}
