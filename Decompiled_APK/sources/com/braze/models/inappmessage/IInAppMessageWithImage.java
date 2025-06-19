package com.braze.models.inappmessage;

import android.graphics.Bitmap;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public interface IInAppMessageWithImage {
    Bitmap getBitmap();

    String getLocalImageUrl();

    String getRemoteImageUrl();

    void setBitmap(Bitmap bitmap);

    void setImageDownloadSuccessful(boolean z);

    void setLocalImageUrl(String str);
}
