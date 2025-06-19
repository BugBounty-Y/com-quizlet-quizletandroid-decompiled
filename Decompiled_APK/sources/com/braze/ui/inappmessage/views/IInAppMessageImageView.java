package com.braze.ui.inappmessage.views;

import com.braze.enums.inappmessage.CropType;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public interface IInAppMessageImageView {
    void setCornersRadiiPx(float f, float f2, float f3, float f4);

    void setCornersRadiusPx(float f);

    void setInAppMessageImageCropType(CropType cropType);
}
