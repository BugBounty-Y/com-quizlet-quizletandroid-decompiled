package com.quizlet.quizletandroid.ui;

import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.view.GestureDetector;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.appcompat.widget.Toolbar;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.appbar.AppBarLayout;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4605i;
import com.quizlet.quizletandroid.databinding.J;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public class FullScreenOverlayActivity extends com.quizlet.baseui.base.f {
    public static final String m;
    public com.quizlet.qutils.image.loading.a l;

    static {
        Intrinsics.checkNotNullExpressionValue("FullScreenOverlayActivity", "getSimpleName(...)");
        m = "FullScreenOverlayActivity";
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return m;
    }

    @Override // com.quizlet.baseui.base.f
    public final Toolbar M() {
        Toolbar toolbar = ((C4605i) K()).e.c;
        Intrinsics.checkNotNullExpressionValue(toolbar, "toolbar");
        return toolbar;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_term_and_image_overlay, (ViewGroup) null, false);
        int i = R.id.test_mode_fullscreen_image;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.test_mode_fullscreen_image, viewInflate);
        if (imageView != null) {
            FrameLayout frameLayout = (FrameLayout) viewInflate;
            i = R.id.test_mode_fullscreen_text;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.test_mode_fullscreen_text, viewInflate);
            if (qTextView != null) {
                i = R.id.transparentAppbar;
                View viewC = AbstractC3375o2.c(R.id.transparentAppbar, viewInflate);
                if (viewC != null) {
                    Toolbar toolbar = (Toolbar) AbstractC3375o2.c(R.id.toolbar, viewC);
                    if (toolbar == null) {
                        throw new NullPointerException("Missing required view with ID: ".concat(viewC.getResources().getResourceName(R.id.toolbar)));
                    }
                    C4605i c4605i = new C4605i(frameLayout, imageView, frameLayout, qTextView, new J((AppBarLayout) viewC, toolbar, 1));
                    Intrinsics.checkNotNullExpressionValue(c4605i, "inflate(...)");
                    return c4605i;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final ImageView O() {
        ImageView testModeFullscreenImage = ((C4605i) K()).b;
        Intrinsics.checkNotNullExpressionValue(testModeFullscreenImage, "testModeFullscreenImage");
        return testModeFullscreenImage;
    }

    @Override // android.app.Activity
    public final void finish() {
        super.finish();
        overridePendingTransition(R.anim.fade_in, R.anim.fade_out_invisible);
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        Bundle extras = getIntent().getExtras();
        String string = extras != null ? extras.getString("overlayImagePath") : null;
        CharSequence charSequence = extras != null ? extras.getCharSequence("overlayText") : null;
        if (string == null || !org.apache.commons.lang3.e.d(string)) {
            O().setVisibility(8);
        } else {
            com.quizlet.qutils.image.loading.a aVar = this.l;
            if (aVar == null) {
                Intrinsics.m("imageLoader");
                throw null;
            }
            ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) aVar).a(O().getContext()).p(string).o(O());
        }
        QTextView testModeFullscreenText = ((C4605i) K()).d;
        Intrinsics.checkNotNullExpressionValue(testModeFullscreenText, "testModeFullscreenText");
        testModeFullscreenText.setText(charSequence);
        WindowManager windowManager = getWindowManager();
        Intrinsics.checkNotNullExpressionValue(windowManager, "getWindowManager(...)");
        O().setMaxHeight(AbstractC3206m6.b(windowManager).getHeight() / 2);
        GestureDetector gestureDetector = new GestureDetector(this, new androidx.camera.view.impl.a(this, 2));
        QTextView testModeFullscreenText2 = ((C4605i) K()).d;
        Intrinsics.checkNotNullExpressionValue(testModeFullscreenText2, "testModeFullscreenText");
        testModeFullscreenText2.setOnTouchListener(new com.amazon.aps.ads.util.adview.d(gestureDetector, 4));
        QTextView testModeFullscreenText3 = ((C4605i) K()).d;
        Intrinsics.checkNotNullExpressionValue(testModeFullscreenText3, "testModeFullscreenText");
        testModeFullscreenText3.setMovementMethod(new ScrollingMovementMethod());
        FrameLayout testModeFullscreenOverlay = ((C4605i) K()).c;
        Intrinsics.checkNotNullExpressionValue(testModeFullscreenOverlay, "testModeFullscreenOverlay");
        testModeFullscreenOverlay.setOnClickListener(new com.braze.ui.inappmessage.d(this, 29));
        if (r() != null) {
            com.bumptech.glide.c cVarR = r();
            Intrinsics.d(cVarR);
            cVarR.u(false);
            com.bumptech.glide.c cVarR2 = r();
            Intrinsics.d(cVarR2);
            cVarR2.s(true);
        }
    }
}
