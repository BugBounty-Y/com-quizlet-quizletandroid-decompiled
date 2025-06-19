package com.quizlet.assembly.widgets.buttons;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.e;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public abstract class d extends ConstraintLayout {
    public final com.quizlet.assembly.databinding.c q;
    public c r;
    public int s;
    public Drawable t;
    public Drawable u;
    public boolean v;
    public ColorStateList w;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public d(@NotNull Context context) {
        this(context, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @NotNull
    public final com.quizlet.assembly.databinding.c getBinding() {
        return this.q;
    }

    public final Drawable getIconLeft() {
        return this.t;
    }

    public final Drawable getIconRight() {
        return this.u;
    }

    public final int getIconSize() {
        return this.s;
    }

    public final ColorStateList getIconTint() {
        return this.w;
    }

    public final boolean getShouldTintIcon() {
        return this.v;
    }

    @NotNull
    public final c getSize() {
        return this.r;
    }

    @NotNull
    public final CharSequence getText() {
        CharSequence text = this.q.d.getText();
        Intrinsics.checkNotNullExpressionValue(text, "getText(...)");
        return text;
    }

    public final void p() throws Resources.NotFoundException {
        Resources resources = getResources();
        setPaddingRelative(resources.getDimensionPixelOffset(this.r.a), resources.getDimensionPixelOffset(this.r.b), resources.getDimensionPixelOffset(this.r.a), resources.getDimensionPixelOffset(this.r.b));
        com.quizlet.assembly.databinding.c cVar = this.q;
        cVar.d.setMinimumHeight(resources.getDimensionPixelSize(this.r.c));
        int dimensionPixelSize = getContext().getResources().getDimensionPixelSize(this.s);
        AppCompatImageView buttonIconLeft = cVar.b;
        Intrinsics.checkNotNullExpressionValue(buttonIconLeft, "buttonIconLeft");
        ViewGroup.LayoutParams layoutParams = buttonIconLeft.getLayoutParams();
        if (layoutParams == null) {
            throw new NullPointerException("null cannot be cast to non-null type androidx.constraintlayout.widget.ConstraintLayout.LayoutParams");
        }
        e eVar = (e) layoutParams;
        ((ViewGroup.MarginLayoutParams) eVar).height = dimensionPixelSize;
        ((ViewGroup.MarginLayoutParams) eVar).width = dimensionPixelSize;
        buttonIconLeft.setLayoutParams(eVar);
        AppCompatImageView buttonIconRight = cVar.c;
        Intrinsics.checkNotNullExpressionValue(buttonIconRight, "buttonIconRight");
        ViewGroup.LayoutParams layoutParams2 = buttonIconRight.getLayoutParams();
        if (layoutParams2 == null) {
            throw new NullPointerException("null cannot be cast to non-null type androidx.constraintlayout.widget.ConstraintLayout.LayoutParams");
        }
        e eVar2 = (e) layoutParams2;
        ((ViewGroup.MarginLayoutParams) eVar2).height = dimensionPixelSize;
        ((ViewGroup.MarginLayoutParams) eVar2).width = dimensionPixelSize;
        buttonIconRight.setLayoutParams(eVar2);
    }

    public final void q(ImageView imageView, Drawable drawable) {
        Drawable drawableMutate;
        imageView.setVisibility(drawable != null ? 0 : 8);
        ColorStateList colorStateList = this.w;
        if (drawable == null || (drawableMutate = drawable.mutate()) == null) {
            drawableMutate = null;
        } else if (this.v) {
            drawableMutate.setTintList(colorStateList);
        }
        imageView.setImageDrawable(drawableMutate);
    }

    public final void setIconLeft(Drawable drawable) {
        this.t = drawable;
        AppCompatImageView buttonIconLeft = this.q.b;
        Intrinsics.checkNotNullExpressionValue(buttonIconLeft, "buttonIconLeft");
        q(buttonIconLeft, this.t);
    }

    public final void setIconRight(Drawable drawable) {
        this.u = drawable;
        AppCompatImageView buttonIconRight = this.q.c;
        Intrinsics.checkNotNullExpressionValue(buttonIconRight, "buttonIconRight");
        q(buttonIconRight, this.u);
    }

    public final void setIconSize(int i) throws Resources.NotFoundException {
        this.s = i;
        p();
    }

    public final void setIconTint(ColorStateList colorStateList) {
        this.w = colorStateList;
        Drawable drawable = this.t;
        com.quizlet.assembly.databinding.c cVar = this.q;
        if (drawable != null) {
            AppCompatImageView buttonIconLeft = cVar.b;
            Intrinsics.checkNotNullExpressionValue(buttonIconLeft, "buttonIconLeft");
            q(buttonIconLeft, this.t);
        }
        if (this.u != null) {
            AppCompatImageView buttonIconRight = cVar.c;
            Intrinsics.checkNotNullExpressionValue(buttonIconRight, "buttonIconRight");
            q(buttonIconRight, this.u);
        }
    }

    public final void setShouldTintIcon(boolean z) {
        this.v = z;
        Drawable drawable = this.t;
        com.quizlet.assembly.databinding.c cVar = this.q;
        if (drawable != null) {
            AppCompatImageView buttonIconLeft = cVar.b;
            Intrinsics.checkNotNullExpressionValue(buttonIconLeft, "buttonIconLeft");
            q(buttonIconLeft, this.t);
        }
        if (this.u != null) {
            AppCompatImageView buttonIconRight = cVar.c;
            Intrinsics.checkNotNullExpressionValue(buttonIconRight, "buttonIconRight");
            q(buttonIconRight, this.u);
        }
    }

    public final void setSize(@NotNull c value) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(value, "value");
        this.r = value;
        p();
    }

    public final void setText(int i) {
        this.q.d.setText(i);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(Context context, AttributeSet attributeSet) throws Resources.NotFoundException {
        super(context, attributeSet, 0);
        Intrinsics.checkNotNullParameter(context, "context");
        LayoutInflater.from(context).inflate(R.layout.view_base_assembly_button, this);
        int i = R.id.buttonIconLeft;
        AppCompatImageView appCompatImageView = (AppCompatImageView) AbstractC3375o2.c(R.id.buttonIconLeft, this);
        if (appCompatImageView != null) {
            i = R.id.buttonIconRight;
            AppCompatImageView appCompatImageView2 = (AppCompatImageView) AbstractC3375o2.c(R.id.buttonIconRight, this);
            if (appCompatImageView2 != null) {
                i = R.id.buttonText;
                TextView textView = (TextView) AbstractC3375o2.c(R.id.buttonText, this);
                if (textView != null) {
                    com.quizlet.assembly.databinding.c cVar = new com.quizlet.assembly.databinding.c(this, appCompatImageView, appCompatImageView2, textView);
                    Intrinsics.checkNotNullExpressionValue(cVar, "inflate(...)");
                    this.q = cVar;
                    this.r = c.e;
                    this.s = R.dimen.ref_size_small;
                    this.v = true;
                    TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.quizlet.assembly.a.i);
                    Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
                    textView.setText(typedArrayObtainStyledAttributes.getString(5));
                    setSize(c.values()[typedArrayObtainStyledAttributes.getInt(4, this.r.ordinal())]);
                    setIconSize(typedArrayObtainStyledAttributes.getResourceId(2, this.r.d));
                    setShouldTintIcon(typedArrayObtainStyledAttributes.getBoolean(3, true));
                    Drawable drawable = typedArrayObtainStyledAttributes.getDrawable(0);
                    if (drawable != null) {
                        setIconLeft(drawable);
                    }
                    Drawable drawable2 = typedArrayObtainStyledAttributes.getDrawable(1);
                    if (drawable2 != null) {
                        setIconRight(drawable2);
                    }
                    p();
                    setFocusable(true);
                    typedArrayObtainStyledAttributes.recycle();
                    return;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(i)));
    }

    public final void setText(@NotNull CharSequence text) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.q.d.setText(text);
    }
}
