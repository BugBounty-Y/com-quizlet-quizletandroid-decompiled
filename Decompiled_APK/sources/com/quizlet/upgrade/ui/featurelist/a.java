package com.quizlet.upgrade.ui.featurelist;

import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.baserecyclerview.c;
import com.quizlet.quizletandroid.R;
import com.quizlet.upgrade.data.q;
import com.quizlet.upgrade.databinding.d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends c {
    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        int i = R.id.description;
        TextView textView = (TextView) AbstractC3375o2.c(R.id.description, view);
        if (textView != null) {
            i = R.id.icon;
            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.icon, view);
            if (imageView != null) {
                i = R.id.title;
                TextView textView2 = (TextView) AbstractC3375o2.c(R.id.title, view);
                if (textView2 != null) {
                    d dVar = new d((ConstraintLayout) view, textView, imageView, textView2);
                    Intrinsics.checkNotNullExpressionValue(dVar, "bind(...)");
                    return dVar;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(q item) {
        Intrinsics.checkNotNullParameter(item, "item");
        d dVar = (d) e();
        dVar.c.setImageResource(item.a);
        dVar.d.setText(item.b);
        dVar.b.setText(item.c);
    }
}
