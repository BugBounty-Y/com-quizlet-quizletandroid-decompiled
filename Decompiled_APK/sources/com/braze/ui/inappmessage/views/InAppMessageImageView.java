package com.braze.ui.inappmessage.views;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import com.braze.enums.inappmessage.CropType;
import com.braze.support.BrazeLogger;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
@SuppressLint({"AppCompatCustomView"})
/* loaded from: classes.dex */
public class InAppMessageImageView extends ImageView implements IInAppMessageImageView {
    private float aspectRatio;

    @NotNull
    private Path clipPath;
    private float[] inAppRadii;

    @NotNull
    private RectF rectf;
    private boolean setToHalfParentHeight;

    public InAppMessageImageView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.clipPath = new Path();
        this.rectf = new RectF();
        this.aspectRatio = -1.0f;
        setAdjustViewBounds(true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String clipCanvasToPath$lambda$0() {
        return "In-app message radii is uninitialized, not clipping path.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String clipCanvasToPath$lambda$1() {
        return "Encountered exception while trying to clip in-app message image";
    }

    private static /* synthetic */ void getSetToHalfParentHeight$annotations() {
    }

    public final boolean clipCanvasToPath(@NotNull Canvas canvas, int i, int i2) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        if (this.inAppRadii == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.ui.inappmessage.listeners.a(13), 7, (Object) null);
            return false;
        }
        try {
            this.clipPath.reset();
            this.rectf.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, i, i2);
            this.clipPath.addRoundRect(this.rectf, getInAppRadii(), Path.Direction.CW);
            canvas.clipPath(this.clipPath);
            return true;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.ui.inappmessage.listeners.a(14), 4, (Object) null);
            return false;
        }
    }

    @NotNull
    public final Path getClipPath() {
        return this.clipPath;
    }

    @NotNull
    public final float[] getInAppRadii() {
        float[] fArr = this.inAppRadii;
        if (fArr != null) {
            return fArr;
        }
        Intrinsics.m("inAppRadii");
        throw null;
    }

    @NotNull
    public final RectF getRectf() {
        return this.rectf;
    }

    @Override // android.widget.ImageView, android.view.View
    public void onDraw(@NotNull Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        clipCanvasToPath(canvas, getWidth(), getHeight());
        super.onDraw(canvas);
    }

    @Override // android.widget.ImageView, android.view.View
    public void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
        if (this.aspectRatio != -1.0f && getMeasuredHeight() > 0 && getMeasuredWidth() > 0) {
            int measuredWidth = getMeasuredWidth();
            setMeasuredDimension(measuredWidth, Math.min(getMeasuredHeight(), (int) (measuredWidth / this.aspectRatio)) + 1);
        } else {
            setMeasuredDimension(getMeasuredWidth(), getMeasuredHeight());
        }
        if (this.setToHalfParentHeight) {
            Intrinsics.e(getParent(), "null cannot be cast to non-null type android.view.View");
            setMeasuredDimension(getMeasuredWidth(), (int) (((View) r5).getHeight() * 0.5d));
        }
    }

    public void setAspectRatio(float f) {
        this.aspectRatio = f;
        requestLayout();
    }

    public final void setClipPath(@NotNull Path path) {
        Intrinsics.checkNotNullParameter(path, "<set-?>");
        this.clipPath = path;
    }

    @Override // com.braze.ui.inappmessage.views.IInAppMessageImageView
    public void setCornersRadiiPx(float f, float f2, float f3, float f4) {
        this.inAppRadii = new float[]{f, f, f2, f2, f3, f3, f4, f4};
    }

    @Override // com.braze.ui.inappmessage.views.IInAppMessageImageView
    public void setCornersRadiusPx(float f) {
        setCornersRadiiPx(f, f, f, f);
    }

    @Override // com.braze.ui.inappmessage.views.IInAppMessageImageView
    public void setInAppMessageImageCropType(CropType cropType) {
        if (cropType == CropType.FIT_CENTER) {
            setScaleType(ImageView.ScaleType.FIT_CENTER);
        } else if (cropType == CropType.CENTER_CROP) {
            setScaleType(ImageView.ScaleType.CENTER_CROP);
        }
    }

    public final void setRectf(@NotNull RectF rectF) {
        Intrinsics.checkNotNullParameter(rectF, "<set-?>");
        this.rectf = rectF;
    }

    public void setToHalfParentHeight(boolean z) {
        this.setToHalfParentHeight = z;
        requestLayout();
    }
}
