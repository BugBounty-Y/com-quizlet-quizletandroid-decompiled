package com.skydoves.balloon.overlay;

import android.app.Activity;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Point;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.view.View;
import com.skydoves.balloon.extensions.ContextExtensionKt;
import com.skydoves.balloon.internals.DefinitionKt;
import com.skydoves.balloon.internals.ViewPropertyDelegate;
import com.skydoves.balloon.internals.ViewPropertyKt;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.v;
import kotlin.reflect.n;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonAnchorOverlayView extends View {
    static final /* synthetic */ n[] $$delegatedProperties;

    @NotNull
    private final ViewPropertyDelegate anchorView$delegate;

    @NotNull
    private final ViewPropertyDelegate anchorViewList$delegate;

    @NotNull
    private final ViewPropertyDelegate balloonOverlayShape$delegate;
    private Bitmap bitmap;
    private boolean invalidated;

    @NotNull
    private final ViewPropertyDelegate overlayColor$delegate;

    @NotNull
    private final ViewPropertyDelegate overlayPadding$delegate;

    @NotNull
    private final ViewPropertyDelegate overlayPaddingColor$delegate;

    @NotNull
    private final ViewPropertyDelegate overlayPaddingShader$delegate;

    @NotNull
    private final ViewPropertyDelegate overlayPosition$delegate;

    @NotNull
    private final Paint paddingColorPaint;

    @NotNull
    private final Paint paint;

    static {
        v vVar = new v(BalloonAnchorOverlayView.class, "anchorView", "getAnchorView()Landroid/view/View;", 0);
        K.a.getClass();
        $$delegatedProperties = new n[]{vVar, new v(BalloonAnchorOverlayView.class, "anchorViewList", "getAnchorViewList()Ljava/util/List;", 0), new v(BalloonAnchorOverlayView.class, "overlayColor", "getOverlayColor()I", 0), new v(BalloonAnchorOverlayView.class, "overlayPaddingColor", "getOverlayPaddingColor()I", 0), new v(BalloonAnchorOverlayView.class, "overlayPaddingShader", "getOverlayPaddingShader()Landroid/graphics/Shader;", 0), new v(BalloonAnchorOverlayView.class, "overlayPadding", "getOverlayPadding()F", 0), new v(BalloonAnchorOverlayView.class, "overlayPosition", "getOverlayPosition()Landroid/graphics/Point;", 0), new v(BalloonAnchorOverlayView.class, "balloonOverlayShape", "getBalloonOverlayShape()Lcom/skydoves/balloon/overlay/BalloonOverlayShape;", 0)};
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public BalloonAnchorOverlayView(@NotNull Context context) {
        this(context, null, 0, 6, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final void addFocusViewInOverlay(View view, Canvas canvas) {
        RectF rectF;
        if (view != null) {
            view.getGlobalVisibleRect(new Rect());
            if (getOverlayPosition() != null) {
                rectF = new RectF(r1.x - getOverlayPadding(), (r1.y - getOverlayPadding()) + getStatusBarHeight(), getOverlayPadding() + view.getWidth() + r1.x, getOverlayPadding() + view.getHeight() + r1.y + getStatusBarHeight());
            } else {
                rectF = new RectF(r0.left - getOverlayPadding(), r0.top - getOverlayPadding(), getOverlayPadding() + r0.right, getOverlayPadding() + r0.bottom);
            }
            float overlayPadding = getOverlayPadding() / 2;
            RectF rectF2 = new RectF(rectF);
            rectF2.inset(overlayPadding, overlayPadding);
            BalloonOverlayShape balloonOverlayShape = getBalloonOverlayShape();
            if (balloonOverlayShape instanceof BalloonOverlayEmpty) {
                return;
            }
            if (balloonOverlayShape instanceof BalloonOverlayRect) {
                canvas.drawRect(rectF, this.paint);
                canvas.drawRect(rectF2, this.paddingColorPaint);
                return;
            }
            if (balloonOverlayShape instanceof BalloonOverlayOval) {
                canvas.drawOval(rectF, this.paint);
                canvas.drawOval(rectF2, this.paddingColorPaint);
                return;
            }
            if (balloonOverlayShape instanceof BalloonOverlayCircle) {
                BalloonOverlayCircle balloonOverlayCircle = (BalloonOverlayCircle) balloonOverlayShape;
                Float radius = balloonOverlayCircle.getRadius();
                if (radius != null) {
                    float fFloatValue = radius.floatValue();
                    canvas.drawCircle(rectF.centerX(), rectF.centerY(), fFloatValue, this.paint);
                    canvas.drawCircle(rectF2.centerX(), rectF2.centerY(), fFloatValue - overlayPadding, this.paddingColorPaint);
                }
                Integer radiusRes = balloonOverlayCircle.getRadiusRes();
                if (radiusRes != null) {
                    int iIntValue = radiusRes.intValue();
                    float fCenterX = rectF.centerX();
                    float fCenterY = rectF.centerY();
                    Context context = getContext();
                    Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
                    canvas.drawCircle(fCenterX, fCenterY, ContextExtensionKt.dimen(context, iIntValue), this.paint);
                    float fCenterX2 = rectF2.centerX();
                    float fCenterY2 = rectF2.centerY();
                    Context context2 = getContext();
                    Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
                    canvas.drawCircle(fCenterX2, fCenterY2, ContextExtensionKt.dimen(context2, iIntValue) - overlayPadding, this.paddingColorPaint);
                    return;
                }
                return;
            }
            if (!(balloonOverlayShape instanceof BalloonOverlayRoundRect)) {
                throw new NoWhenBranchMatchedException();
            }
            BalloonOverlayRoundRect balloonOverlayRoundRect = (BalloonOverlayRoundRect) balloonOverlayShape;
            Pair<Float, Float> radiusPair = balloonOverlayRoundRect.getRadiusPair();
            if (radiusPair != null) {
                Object obj = radiusPair.a;
                float fFloatValue2 = ((Number) obj).floatValue();
                Object obj2 = radiusPair.b;
                canvas.drawRoundRect(rectF, fFloatValue2, ((Number) obj2).floatValue(), this.paint);
                canvas.drawRoundRect(rectF2, ((Number) obj).floatValue() - overlayPadding, ((Number) obj2).floatValue() - overlayPadding, this.paddingColorPaint);
            }
            Pair<Integer, Integer> radiusResPair = balloonOverlayRoundRect.getRadiusResPair();
            if (radiusResPair != null) {
                Context context3 = getContext();
                Intrinsics.checkNotNullExpressionValue(context3, "getContext(...)");
                Object obj3 = radiusResPair.a;
                float fDimen = ContextExtensionKt.dimen(context3, ((Number) obj3).intValue());
                Context context4 = getContext();
                Intrinsics.checkNotNullExpressionValue(context4, "getContext(...)");
                Object obj4 = radiusResPair.b;
                canvas.drawRoundRect(rectF, fDimen, ContextExtensionKt.dimen(context4, ((Number) obj4).intValue()), this.paint);
                Context context5 = getContext();
                Intrinsics.checkNotNullExpressionValue(context5, "getContext(...)");
                float fDimen2 = ContextExtensionKt.dimen(context5, ((Number) obj3).intValue()) - overlayPadding;
                Context context6 = getContext();
                Intrinsics.checkNotNullExpressionValue(context6, "getContext(...)");
                canvas.drawRoundRect(rectF2, fDimen2, ContextExtensionKt.dimen(context6, ((Number) obj4).intValue()) - overlayPadding, this.paddingColorPaint);
            }
        }
    }

    private final int getStatusBarHeight() {
        Rect rect = new Rect();
        Context context = getContext();
        if (!(context instanceof Activity)) {
            return 0;
        }
        ((Activity) context).getWindow().getDecorView().getWindowVisibleDisplayFrame(rect);
        return rect.top;
    }

    private final void prepareBitmap() {
        if (getWidth() == 0 || getHeight() == 0) {
            return;
        }
        View anchorView = getAnchorView();
        if (anchorView == null || anchorView.getWidth() != 0) {
            View anchorView2 = getAnchorView();
            if (anchorView2 == null || anchorView2.getHeight() != 0) {
                Bitmap bitmap = this.bitmap;
                if (bitmap != null && !bitmap.isRecycled()) {
                    bitmap.recycle();
                }
                Bitmap bitmapCreateBitmap = Bitmap.createBitmap(getWidth(), getHeight(), Bitmap.Config.ARGB_8888);
                this.bitmap = bitmapCreateBitmap;
                Canvas canvas = new Canvas(bitmapCreateBitmap);
                Paint paint = this.paint;
                paint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.SRC_OUT));
                paint.setColor(getOverlayColor());
                canvas.drawRect(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, getWidth(), getHeight(), this.paint);
                Paint paint2 = this.paint;
                paint2.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
                paint2.setColor(0);
                Paint paint3 = this.paddingColorPaint;
                paint3.setColor(getOverlayPaddingColor());
                paint3.setStyle(Paint.Style.STROKE);
                paint3.setStrokeWidth(getOverlayPadding());
                paint3.setShader(getOverlayPaddingShader());
                List<View> anchorViewList = getAnchorViewList();
                if (anchorViewList == null || anchorViewList.isEmpty()) {
                    addFocusViewInOverlay(getAnchorView(), canvas);
                } else {
                    List<View> anchorViewList2 = getAnchorViewList();
                    if (anchorViewList2 != null) {
                        Iterator<T> it2 = anchorViewList2.iterator();
                        while (it2.hasNext()) {
                            addFocusViewInOverlay((View) it2.next(), canvas);
                        }
                    }
                }
                this.invalidated = false;
            }
        }
    }

    @Override // android.view.View
    public void dispatchDraw(@NotNull Canvas canvas) {
        Bitmap bitmap;
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        if (this.invalidated || (bitmap = this.bitmap) == null || (bitmap != null && bitmap.isRecycled())) {
            prepareBitmap();
        }
        Bitmap bitmap2 = this.bitmap;
        if (bitmap2 == null || bitmap2.isRecycled()) {
            return;
        }
        canvas.drawBitmap(bitmap2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, (Paint) null);
    }

    public final void forceInvalidate() {
        this.invalidated = true;
        invalidate();
    }

    public final View getAnchorView() {
        return (View) this.anchorView$delegate.getValue(this, $$delegatedProperties[0]);
    }

    public final List<View> getAnchorViewList() {
        return (List) this.anchorViewList$delegate.getValue(this, $$delegatedProperties[1]);
    }

    @NotNull
    public final BalloonOverlayShape getBalloonOverlayShape() {
        return (BalloonOverlayShape) this.balloonOverlayShape$delegate.getValue(this, $$delegatedProperties[7]);
    }

    public final int getOverlayColor() {
        return ((Number) this.overlayColor$delegate.getValue(this, $$delegatedProperties[2])).intValue();
    }

    public final float getOverlayPadding() {
        return ((Number) this.overlayPadding$delegate.getValue(this, $$delegatedProperties[5])).floatValue();
    }

    public final int getOverlayPaddingColor() {
        return ((Number) this.overlayPaddingColor$delegate.getValue(this, $$delegatedProperties[3])).intValue();
    }

    public final Shader getOverlayPaddingShader() {
        return (Shader) this.overlayPaddingShader$delegate.getValue(this, $$delegatedProperties[4]);
    }

    public final Point getOverlayPosition() {
        return (Point) this.overlayPosition$delegate.getValue(this, $$delegatedProperties[6]);
    }

    @Override // android.view.View
    public void onLayout(boolean z, int i, int i2, int i3, int i4) {
        super.onLayout(z, i, i2, i3, i4);
        this.invalidated = true;
    }

    public final void setAnchorView(View view) {
        this.anchorView$delegate.setValue(this, $$delegatedProperties[0], view);
    }

    public final void setAnchorViewList(List<? extends View> list) {
        this.anchorViewList$delegate.setValue(this, $$delegatedProperties[1], list);
    }

    public final void setBalloonOverlayShape(@NotNull BalloonOverlayShape balloonOverlayShape) {
        Intrinsics.checkNotNullParameter(balloonOverlayShape, "<set-?>");
        this.balloonOverlayShape$delegate.setValue(this, $$delegatedProperties[7], balloonOverlayShape);
    }

    public final void setOverlayColor(int i) {
        this.overlayColor$delegate.setValue(this, $$delegatedProperties[2], Integer.valueOf(i));
    }

    public final void setOverlayPadding(float f) {
        this.overlayPadding$delegate.setValue(this, $$delegatedProperties[5], Float.valueOf(f));
    }

    public final void setOverlayPaddingColor(int i) {
        this.overlayPaddingColor$delegate.setValue(this, $$delegatedProperties[3], Integer.valueOf(i));
    }

    public final void setOverlayPaddingShader(Shader shader) {
        this.overlayPaddingShader$delegate.setValue(this, $$delegatedProperties[4], shader);
    }

    public final void setOverlayPosition(Point point) {
        this.overlayPosition$delegate.setValue(this, $$delegatedProperties[6], point);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public BalloonAnchorOverlayView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0, 4, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ BalloonAnchorOverlayView(Context context, AttributeSet attributeSet, int i, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i2 & 2) != 0 ? null : attributeSet, (i2 & 4) != 0 ? 0 : i);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BalloonAnchorOverlayView(@NotNull Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        Intrinsics.checkNotNullParameter(context, "context");
        this.anchorView$delegate = ViewPropertyKt.viewProperty(this, null);
        this.anchorViewList$delegate = ViewPropertyKt.viewProperty(this, null);
        this.overlayColor$delegate = ViewPropertyKt.viewProperty(this, 0);
        this.overlayPaddingColor$delegate = ViewPropertyKt.viewProperty(this, 0);
        this.overlayPaddingShader$delegate = ViewPropertyKt.viewProperty(this, null);
        this.overlayPadding$delegate = ViewPropertyKt.viewProperty(this, Float.valueOf(DefinitionKt.NO_Float_VALUE));
        this.overlayPosition$delegate = ViewPropertyKt.viewProperty(this, null);
        this.balloonOverlayShape$delegate = ViewPropertyKt.viewProperty(this, BalloonOverlayOval.INSTANCE);
        Paint paint = new Paint(1);
        this.paint = paint;
        Paint paint2 = new Paint(1);
        this.paddingColorPaint = paint2;
        paint.setAntiAlias(true);
        paint.setFilterBitmap(true);
        paint.setDither(true);
        paint2.setAntiAlias(true);
        paint2.setFilterBitmap(true);
        paint2.setDither(true);
    }
}
