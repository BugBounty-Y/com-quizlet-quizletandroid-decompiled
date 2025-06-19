package com.quizlet.scandocument.ui;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.scandocument.model.k;
import com.quizlet.scandocument.model.m;
import com.quizlet.scandocument.model.n;
import com.quizlet.scandocument.model.o;
import com.quizlet.scandocument.model.p;
import com.quizlet.scandocument.model.q;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class OcrDocumentView extends ConstraintLayout {
    public final View q;
    public final QButton r;
    public final View s;
    public final View t;
    public final View u;
    public final OcrImageView v;
    public final ImageView w;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public OcrDocumentView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @NotNull
    public final ImageView getChangeImageButton() {
        return this.w;
    }

    @NotNull
    public final View getLoadingView() {
        return this.s;
    }

    @NotNull
    public final OcrImageView getOcrImageView() {
        return this.v;
    }

    @NotNull
    public final View getOnboardingView() {
        return this.t;
    }

    @NotNull
    public final View getReadyView() {
        return this.u;
    }

    @NotNull
    public final QButton getScanDocumentCtaButton() {
        return this.r;
    }

    @NotNull
    public final View getScanDocumentCtaScreen() {
        return this.q;
    }

    public final void p() {
        this.q.setVisibility(0);
        this.s.setVisibility(8);
        this.u.setVisibility(8);
        this.t.setVisibility(8);
        this.r.setText(getContext().getString(R.string.get_started_button));
    }

    public final void q(q newState) {
        Intrinsics.checkNotNullParameter(newState, "newState");
        if (newState instanceof p) {
            p();
            return;
        }
        boolean z = newState instanceof n;
        View view = this.t;
        View view2 = this.u;
        View view3 = this.q;
        View view4 = this.s;
        if (z) {
            view4.setVisibility(0);
            view3.setVisibility(8);
            view2.setVisibility(8);
            view.setVisibility(8);
            return;
        }
        if (!(newState instanceof k)) {
            if (!(newState instanceof m) && !Intrinsics.b(newState, o.a)) {
                throw new NoWhenBranchMatchedException();
            }
            return;
        }
        k kVar = (k) newState;
        view2.setVisibility(0);
        view3.setVisibility(8);
        view4.setVisibility(8);
        view2.setVisibility(0);
        kVar.getClass();
        view.setVisibility(8);
        OcrImageView ocrImageView = this.v;
        if (ocrImageView.hasImage()) {
            ocrImageView.recycle();
        }
        ocrImageView.setScanDocument(kVar.a);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public OcrDocumentView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public OcrDocumentView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        View viewInflate = View.inflate(context, R.layout.view_ocr_document, this);
        this.q = viewInflate.findViewById(R.id.scanDocumentCtaScreen);
        this.r = (QButton) viewInflate.findViewById(R.id.ocrDocumentCtaButton);
        this.s = viewInflate.findViewById(R.id.loadingScreen);
        this.t = viewInflate.findViewById(R.id.onboardingScreen);
        this.v = (OcrImageView) viewInflate.findViewById(R.id.ocrDocumentImage);
        this.u = viewInflate.findViewById(R.id.readyScreen);
        ImageView imageView = (ImageView) viewInflate.findViewById(R.id.changeImageButton);
        this.w = imageView;
        imageView.setImageDrawable(com.quizlet.themes.extensions.a.c(context, R.drawable.ic_sys_image, R.attr.AssemblyGray200));
    }
}
