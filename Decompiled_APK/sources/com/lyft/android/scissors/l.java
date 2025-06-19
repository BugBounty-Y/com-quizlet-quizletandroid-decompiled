package com.lyft.android.scissors;

import android.net.Uri;
import android.widget.ImageView;
import com.nostra13.universalimageloader.core.DisplayImageOptions;
import com.nostra13.universalimageloader.core.ImageLoader;
import com.nostra13.universalimageloader.core.display.BitmapDisplayer;

/* loaded from: classes2.dex */
public final class l implements a {
    public final ImageLoader a;
    public final BitmapDisplayer b;

    public l(ImageLoader imageLoader, BitmapDisplayer bitmapDisplayer) {
        this.a = imageLoader;
        this.b = bitmapDisplayer;
    }

    public static l b(CropView cropView) {
        ImageLoader imageLoader = ImageLoader.getInstance();
        cropView.getViewportWidth();
        cropView.getViewportHeight();
        return new l(imageLoader, m.a());
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.lyft.android.scissors.a
    public final void a(Uri uri, ImageView imageView) {
        DisplayImageOptions displayImageOptionsBuild = new DisplayImageOptions.Builder().cacheInMemory(false).cacheOnDisk(false).displayer(this.b).build();
        if (uri != 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.h(uri, "Unsupported model "));
        }
        this.a.displayImage((String) uri, imageView, displayImageOptionsBuild);
    }
}
