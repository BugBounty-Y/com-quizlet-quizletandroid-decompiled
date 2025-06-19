package com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer;

import android.view.View;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.explanations.databinding.s;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;

/* loaded from: classes2.dex */
public final class g extends com.quizlet.baserecyclerview.c {
    public final com.quizlet.qutils.image.loading.a d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(View view, com.quizlet.qutils.image.loading.a imageLoader) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        this.d = imageLoader;
        final int i = 0;
        l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.f
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                    case 0:
                        return ((s) this.b.e()).b;
                    case 1:
                        ImageView textbookImage = ((s) this.b.e()).c;
                        Intrinsics.checkNotNullExpressionValue(textbookImage, "textbookImage");
                        return textbookImage;
                    default:
                        return ((s) this.b.e()).d;
                }
            }
        });
        final int i2 = 1;
        l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.f
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        return ((s) this.b.e()).b;
                    case 1:
                        ImageView textbookImage = ((s) this.b.e()).c;
                        Intrinsics.checkNotNullExpressionValue(textbookImage, "textbookImage");
                        return textbookImage;
                    default:
                        return ((s) this.b.e()).d;
                }
            }
        });
        final int i3 = 2;
        l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.f
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i3) {
                    case 0:
                        return ((s) this.b.e()).b;
                    case 1:
                        ImageView textbookImage = ((s) this.b.e()).c;
                        Intrinsics.checkNotNullExpressionValue(textbookImage, "textbookImage");
                        return textbookImage;
                    default:
                        return ((s) this.b.e()).d;
                }
            }
        });
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        if (obj != null) {
            throw new ClassCastException();
        }
        Intrinsics.checkNotNullParameter(null, "item");
        ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) this.d).a(this.b);
        throw null;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        int i = R.id.textbookButton;
        ConstraintLayout constraintLayout = (ConstraintLayout) AbstractC3375o2.c(R.id.textbookButton, view);
        if (constraintLayout != null) {
            i = R.id.textbookImage;
            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.textbookImage, view);
            if (imageView != null) {
                i = R.id.textbookSection;
                if (((QTextView) AbstractC3375o2.c(R.id.textbookSection, view)) != null) {
                    i = R.id.textbookTitleText;
                    QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.textbookTitleText, view);
                    if (qTextView != null) {
                        s sVar = new s((ConstraintLayout) view, constraintLayout, imageView, qTextView);
                        Intrinsics.checkNotNullExpressionValue(sVar, "bind(...)");
                        return sVar;
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }
}
