package com.braze.images;

import android.graphics.Bitmap;
import android.view.View;
import android.widget.ImageView;
import com.braze.enums.BrazeViewBounds;
import com.braze.support.BrazeImageUtils;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f implements View.OnLayoutChangeListener {
    public final /* synthetic */ BrazeViewBounds a;
    public final /* synthetic */ ImageView b;
    public final /* synthetic */ Bitmap c;

    public f(BrazeViewBounds brazeViewBounds, ImageView imageView, Bitmap bitmap) {
        this.a = brazeViewBounds;
        this.b = imageView;
        this.c = bitmap;
    }

    public static final void a(Bitmap bitmap, ImageView imageView) {
        BrazeImageUtils.resizeImageViewToBitmapDimensions(bitmap, imageView);
    }

    @Override // android.view.View.OnLayoutChangeListener
    public final void onLayoutChange(View v, int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8) {
        Intrinsics.checkNotNullParameter(v, "v");
        if (this.a == BrazeViewBounds.BASE_CARD_VIEW) {
            ImageView imageView = this.b;
            imageView.post(new androidx.credentials.playservices.controllers.c(12, this.c, imageView));
        }
        v.removeOnLayoutChangeListener(this);
    }
}
