package com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer;

import android.view.ViewGroup;
import androidx.recyclerview.widget.AbstractC1358c;
import androidx.recyclerview.widget.F0;
import com.onetrust.otpublishers.headless.UI.adapter.s;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends com.quizlet.baserecyclerview.b {
    public final com.quizlet.qutils.image.loading.a c;

    public a(com.quizlet.qutils.image.loading.a imageLoader) {
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        s diffUtilCallback = new s(2);
        Intrinsics.checkNotNullParameter(diffUtilCallback, "diffUtilCallback");
        super((AbstractC1358c) diffUtilCallback);
        this.c = imageLoader;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        g holder = (g) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        if (d(i) != null) {
            throw new ClassCastException();
        }
        Intrinsics.e(null, "null cannot be cast to non-null type com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.TextbookExtraInfo");
        holder.getClass();
        Intrinsics.checkNotNullParameter(null, "item");
        ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) holder.d).a(holder.b);
        throw null;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        return new g(com.quizlet.baserecyclerview.b.g(parent, R.layout.listitem_exercise_detail_textbook), this.c);
    }
}
