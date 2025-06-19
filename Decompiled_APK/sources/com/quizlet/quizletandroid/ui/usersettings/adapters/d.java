package com.quizlet.quizletandroid.ui.usersettings.adapters;

import android.view.View;
import android.widget.ImageView;
import android.widget.RadioButton;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.api.model.ProfileImage;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.c0;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.h;
import com.quizlet.quizletandroid.ui.common.views.SquareFrameLayout;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class d extends com.quizlet.baserecyclerview.c {
    public final c d;
    public final com.quizlet.qutils.image.loading.a e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(View view, c presenter) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(presenter, "presenter");
        this.d = presenter;
        this.e = (com.quizlet.qutils.image.loading.a) ((u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, this.itemView.getContext().getApplicationContext()))).s.get();
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        int i = R.id.image_selector;
        RadioButton radioButton = (RadioButton) AbstractC3375o2.c(R.id.image_selector, view);
        if (radioButton != null) {
            i = R.id.image_view;
            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.image_view, view);
            if (imageView != null) {
                c0 c0Var = new c0((SquareFrameLayout) view, radioButton, imageView);
                Intrinsics.checkNotNullExpressionValue(c0Var, "bind(...)");
                return c0Var;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(ProfileImage item) {
        Intrinsics.checkNotNullParameter(item, "item");
        c0 c0Var = (c0) e();
        String url = item.getUrl();
        Intrinsics.d(url);
        if (StringsKt.O(url)) {
            c0Var.c.setImageDrawable(null);
        } else {
            com.quizlet.qutils.image.loading.a aVar = this.e;
            if (aVar == null) {
                Intrinsics.m("mImageLoader");
                throw null;
            }
            ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) aVar).a(this.a.getContext()).p(url).o(c0Var.c);
        }
        RadioButton imageSelector = c0Var.b;
        Intrinsics.checkNotNullExpressionValue(imageSelector, "imageSelector");
        c cVar = this.d;
        boolean z = item == cVar.d(cVar.d);
        if (z) {
            imageSelector.setChecked(true);
        }
        imageSelector.setVisibility(z ? 0 : 8);
        this.itemView.setOnClickListener(new h(this, 25));
    }
}
