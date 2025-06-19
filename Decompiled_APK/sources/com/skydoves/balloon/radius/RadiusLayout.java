package com.skydoves.balloon.radius;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.widget.FrameLayout;
import com.skydoves.balloon.internals.DefinitionKt;
import com.skydoves.balloon.internals.ViewPropertyDelegate;
import com.skydoves.balloon.internals.ViewPropertyKt;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.v;
import kotlin.reflect.n;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RadiusLayout extends FrameLayout {
    static final /* synthetic */ n[] $$delegatedProperties;

    @NotNull
    private final Path path;

    @NotNull
    private final ViewPropertyDelegate radius$delegate;

    static {
        v vVar = new v(RadiusLayout.class, "radius", "getRadius()F", 0);
        K.a.getClass();
        $$delegatedProperties = new n[]{vVar};
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public RadiusLayout(@NotNull Context context) {
        this(context, null, 0, 6, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @Override // android.view.ViewGroup, android.view.View
    public void dispatchDraw(@NotNull Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        canvas.clipPath(this.path);
        super.dispatchDraw(canvas);
    }

    public final float getRadius() {
        return ((Number) this.radius$delegate.getValue(this, $$delegatedProperties[0])).floatValue();
    }

    @Override // android.view.View
    public void onSizeChanged(int i, int i2, int i3, int i4) {
        super.onSizeChanged(i, i2, i3, i4);
        this.path.addRoundRect(new RectF(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, i, i2), getRadius(), getRadius(), Path.Direction.CW);
    }

    public final void setRadius(float f) {
        this.radius$delegate.setValue(this, $$delegatedProperties[0], Float.valueOf(f));
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public RadiusLayout(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0, 4, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ RadiusLayout(Context context, AttributeSet attributeSet, int i, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i2 & 2) != 0 ? null : attributeSet, (i2 & 4) != 0 ? 0 : i);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RadiusLayout(@NotNull Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        Intrinsics.checkNotNullParameter(context, "context");
        this.path = new Path();
        this.radius$delegate = ViewPropertyKt.viewProperty(this, Float.valueOf(DefinitionKt.NO_Float_VALUE));
    }
}
