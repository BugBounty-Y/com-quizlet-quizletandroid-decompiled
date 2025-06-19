package com.quizlet.edgy.databinding;

import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class f implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final ImageView b;
    public final TextView c;
    public final TextView d;
    public final TextView e;

    public f(ConstraintLayout constraintLayout, ImageView imageView, TextView textView, TextView textView2, TextView textView3) {
        this.a = constraintLayout;
        this.b = imageView;
        this.c = textView;
        this.d = textView2;
        this.e = textView3;
    }

    public static f a(View view) {
        int i = R.id.btnRemove;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.btnRemove, view);
        if (imageView != null) {
            i = R.id.courseCode;
            TextView textView = (TextView) AbstractC3375o2.c(R.id.courseCode, view);
            if (textView != null) {
                i = R.id.courseCodeOrName;
                TextView textView2 = (TextView) AbstractC3375o2.c(R.id.courseCodeOrName, view);
                if (textView2 != null) {
                    i = R.id.courseImage;
                    if (((ImageView) AbstractC3375o2.c(R.id.courseImage, view)) != null) {
                        i = R.id.courseName;
                        TextView textView3 = (TextView) AbstractC3375o2.c(R.id.courseName, view);
                        if (textView3 != null) {
                            return new f((ConstraintLayout) view, imageView, textView, textView2, textView3);
                        }
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
