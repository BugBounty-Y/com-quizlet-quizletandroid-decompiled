package androidx.cardview.widget;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.compose.foundation.text.input.internal.u;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public class CardView extends FrameLayout {
    public static final int[] f = {R.attr.colorBackground};
    public static final com.google.firebase.perf.logging.b g = new com.google.firebase.perf.logging.b(2);
    public boolean a;
    public boolean b;
    public final Rect c;
    public final Rect d;
    public final u e;

    public CardView(@NonNull Context context) {
        this(context, null);
    }

    @NonNull
    public ColorStateList getCardBackgroundColor() {
        return ((a) ((Drawable) this.e.b)).h;
    }

    public float getCardElevation() {
        return ((CardView) this.e.c).getElevation();
    }

    public int getContentPaddingBottom() {
        return this.c.bottom;
    }

    public int getContentPaddingLeft() {
        return this.c.left;
    }

    public int getContentPaddingRight() {
        return this.c.right;
    }

    public int getContentPaddingTop() {
        return this.c.top;
    }

    public float getMaxCardElevation() {
        return ((a) ((Drawable) this.e.b)).e;
    }

    public boolean getPreventCornerOverlap() {
        return this.b;
    }

    public float getRadius() {
        return ((a) ((Drawable) this.e.b)).a;
    }

    public boolean getUseCompatPadding() {
        return this.a;
    }

    @Override // android.widget.FrameLayout, android.view.View
    public void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
    }

    public void setCardBackgroundColor(int i) {
        ColorStateList colorStateListValueOf = ColorStateList.valueOf(i);
        a aVar = (a) ((Drawable) this.e.b);
        if (colorStateListValueOf == null) {
            aVar.getClass();
            colorStateListValueOf = ColorStateList.valueOf(0);
        }
        aVar.h = colorStateListValueOf;
        aVar.b.setColor(colorStateListValueOf.getColorForState(aVar.getState(), aVar.h.getDefaultColor()));
        aVar.invalidateSelf();
    }

    public void setCardElevation(float f2) {
        ((CardView) this.e.c).setElevation(f2);
    }

    public void setMaxCardElevation(float f2) {
        g.m(this.e, f2);
    }

    @Override // android.view.View
    public void setMinimumHeight(int i) {
        super.setMinimumHeight(i);
    }

    @Override // android.view.View
    public void setMinimumWidth(int i) {
        super.setMinimumWidth(i);
    }

    @Override // android.view.View
    public final void setPadding(int i, int i2, int i3, int i4) {
    }

    @Override // android.view.View
    public final void setPaddingRelative(int i, int i2, int i3, int i4) {
    }

    public void setPreventCornerOverlap(boolean z) {
        if (z != this.b) {
            this.b = z;
            com.google.firebase.perf.logging.b bVar = g;
            u uVar = this.e;
            bVar.m(uVar, ((a) ((Drawable) uVar.b)).e);
        }
    }

    public void setRadius(float f2) {
        a aVar = (a) ((Drawable) this.e.b);
        if (f2 == aVar.a) {
            return;
        }
        aVar.a = f2;
        aVar.b(null);
        aVar.invalidateSelf();
    }

    public void setUseCompatPadding(boolean z) {
        if (this.a != z) {
            this.a = z;
            com.google.firebase.perf.logging.b bVar = g;
            u uVar = this.e;
            bVar.m(uVar, ((a) ((Drawable) uVar.b)).e);
        }
    }

    public CardView(@NonNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, com.quizlet.quizletandroid.R.attr.cardViewStyle);
    }

    public CardView(Context context, AttributeSet attributeSet, int i) throws Resources.NotFoundException {
        int color;
        ColorStateList colorStateListValueOf;
        super(context, attributeSet, i);
        Rect rect = new Rect();
        this.c = rect;
        this.d = new Rect();
        u uVar = new u(this, 3);
        this.e = uVar;
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, androidx.cardview.a.a, i, com.quizlet.quizletandroid.R.style.CardView);
        if (typedArrayObtainStyledAttributes.hasValue(2)) {
            colorStateListValueOf = typedArrayObtainStyledAttributes.getColorStateList(2);
        } else {
            TypedArray typedArrayObtainStyledAttributes2 = getContext().obtainStyledAttributes(f);
            int color2 = typedArrayObtainStyledAttributes2.getColor(0, 0);
            typedArrayObtainStyledAttributes2.recycle();
            float[] fArr = new float[3];
            Color.colorToHSV(color2, fArr);
            if (fArr[2] > 0.5f) {
                color = getResources().getColor(com.quizlet.quizletandroid.R.color.cardview_light_background);
            } else {
                color = getResources().getColor(com.quizlet.quizletandroid.R.color.cardview_dark_background);
            }
            colorStateListValueOf = ColorStateList.valueOf(color);
        }
        float dimension = typedArrayObtainStyledAttributes.getDimension(3, DefinitionKt.NO_Float_VALUE);
        float dimension2 = typedArrayObtainStyledAttributes.getDimension(4, DefinitionKt.NO_Float_VALUE);
        float dimension3 = typedArrayObtainStyledAttributes.getDimension(5, DefinitionKt.NO_Float_VALUE);
        this.a = typedArrayObtainStyledAttributes.getBoolean(7, false);
        this.b = typedArrayObtainStyledAttributes.getBoolean(6, true);
        int dimensionPixelSize = typedArrayObtainStyledAttributes.getDimensionPixelSize(8, 0);
        rect.left = typedArrayObtainStyledAttributes.getDimensionPixelSize(10, dimensionPixelSize);
        rect.top = typedArrayObtainStyledAttributes.getDimensionPixelSize(12, dimensionPixelSize);
        rect.right = typedArrayObtainStyledAttributes.getDimensionPixelSize(11, dimensionPixelSize);
        rect.bottom = typedArrayObtainStyledAttributes.getDimensionPixelSize(9, dimensionPixelSize);
        dimension3 = dimension2 > dimension3 ? dimension2 : dimension3;
        typedArrayObtainStyledAttributes.getDimensionPixelSize(0, 0);
        typedArrayObtainStyledAttributes.getDimensionPixelSize(1, 0);
        typedArrayObtainStyledAttributes.recycle();
        com.google.firebase.perf.logging.b bVar = g;
        a aVar = new a(colorStateListValueOf, dimension);
        uVar.b = aVar;
        setBackgroundDrawable(aVar);
        setClipToOutline(true);
        setElevation(dimension2);
        bVar.m(uVar, dimension3);
    }

    public void setCardBackgroundColor(ColorStateList colorStateList) {
        a aVar = (a) ((Drawable) this.e.b);
        if (colorStateList == null) {
            aVar.getClass();
            colorStateList = ColorStateList.valueOf(0);
        }
        aVar.h = colorStateList;
        aVar.b.setColor(colorStateList.getColorForState(aVar.getState(), aVar.h.getDefaultColor()));
        aVar.invalidateSelf();
    }
}
