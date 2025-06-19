package com.lyft.android.scissors;

import android.net.Uri;
import android.widget.ImageView;
import com.squareup.picasso.Picasso;
import com.squareup.picasso.Transformation;

/* loaded from: classes2.dex */
public final class h implements a {
    public final Picasso a;
    public final Transformation b;

    public h(Picasso picasso, Transformation transformation) {
        this.a = picasso;
        this.b = transformation;
    }

    public static h b(CropView cropView) {
        Picasso picassoWith = Picasso.with(cropView.getContext());
        cropView.getViewportWidth();
        cropView.getViewportHeight();
        return new h(picassoWith, i.a());
    }

    @Override // com.lyft.android.scissors.a
    public final void a(Uri uri, ImageView imageView) {
        if (uri == null && uri != null) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.h(uri, "Unsupported model "));
        }
        this.a.load(uri).skipMemoryCache().transform(this.b).into(imageView);
    }
}
