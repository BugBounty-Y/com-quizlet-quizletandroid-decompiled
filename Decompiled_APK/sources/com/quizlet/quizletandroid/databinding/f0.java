package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.RelativeLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.quizletandroid.ui.setcreation.views.OcrCardView;
import com.quizlet.scandocument.ui.OcrDocumentView;
import com.quizlet.scandocument.ui.OcrToolbarView;

/* loaded from: classes3.dex */
public final class f0 implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final RelativeLayout b;
    public final OcrCardView c;
    public final OcrToolbarView d;
    public final OcrDocumentView e;

    public f0(ConstraintLayout constraintLayout, RelativeLayout relativeLayout, OcrCardView ocrCardView, OcrToolbarView ocrToolbarView, OcrDocumentView ocrDocumentView) {
        this.a = constraintLayout;
        this.b = relativeLayout;
        this.c = ocrCardView;
        this.d = ocrToolbarView;
        this.e = ocrDocumentView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
