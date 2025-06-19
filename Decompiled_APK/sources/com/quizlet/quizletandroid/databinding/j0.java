package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.ImageView;
import androidx.cardview.widget.CardView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class j0 implements androidx.viewbinding.a {
    public final View a;
    public final QTextView b;
    public final ImageView c;
    public final CardView d;
    public final QTextView e;

    public j0(View view, ImageView imageView, CardView cardView, QTextView qTextView, QTextView qTextView2) {
        this.a = view;
        this.b = qTextView;
        this.c = imageView;
        this.d = cardView;
        this.e = qTextView2;
    }

    public static j0 a(View view) {
        int i = R.id.definition;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.definition, view);
        if (qTextView != null) {
            i = R.id.image;
            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.image, view);
            if (imageView != null) {
                i = R.id.imageContainer;
                CardView cardView = (CardView) AbstractC3375o2.c(R.id.imageContainer, view);
                if (cardView != null) {
                    i = R.id.word;
                    QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.word, view);
                    if (qTextView2 != null) {
                        return new j0(view, imageView, cardView, qTextView, qTextView2);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
