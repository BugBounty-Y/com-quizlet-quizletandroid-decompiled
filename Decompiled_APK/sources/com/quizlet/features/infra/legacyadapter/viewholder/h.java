package com.quizlet.features.infra.legacyadapter.viewholder;

import android.view.View;
import android.widget.LinearLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int d = 0;

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.listitem_section_header_text, view);
        if (qTextView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.listitem_section_header_text)));
        }
        com.quizlet.features.infra.legacyadapter.databinding.b bVar = new com.quizlet.features.infra.legacyadapter.databinding.b((LinearLayout) view, qTextView);
        Intrinsics.checkNotNullExpressionValue(bVar, "bind(...)");
        return bVar;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(com.quizlet.features.infra.legacyadapter.section.b item) {
        Intrinsics.checkNotNullParameter(item, "item");
        item.getClass();
        String upperCase = item.b.b(System.currentTimeMillis(), item.c).toString().toUpperCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
        ((com.quizlet.features.infra.legacyadapter.databinding.b) e()).b.setText(upperCase);
    }
}
