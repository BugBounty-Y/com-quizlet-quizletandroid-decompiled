package com.pubmatic.sdk.common.network;

import android.graphics.Bitmap;
import android.widget.ImageView;

/* loaded from: classes2.dex */
public class b extends a {
    private int i;
    private int j;
    private ImageView.ScaleType k;
    private Bitmap.Config l;

    public Bitmap.Config getDecodeConfig() {
        return this.l;
    }

    public int getMaxHeight() {
        return this.j;
    }

    public int getMaxWidth() {
        return this.i;
    }

    public ImageView.ScaleType getScaleType() {
        return this.k;
    }

    public void setDecodeConfig(Bitmap.Config config) {
        this.l = config;
    }

    public void setMaxHeight(int i) {
        this.j = i;
    }

    public void setMaxWidth(int i) {
        this.i = i;
    }

    public void setScaleType(ImageView.ScaleType scaleType) {
        this.k = scaleType;
    }
}
