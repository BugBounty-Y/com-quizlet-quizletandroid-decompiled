package androidx.vectordrawable.graphics.drawable;

import android.content.res.ColorStateList;
import android.graphics.drawable.Animatable2;
import android.graphics.drawable.Drawable;
import com.google.android.material.checkbox.MaterialCheckBox;

/* loaded from: classes.dex */
public final class b extends Animatable2.AnimationCallback {
    public final /* synthetic */ com.google.android.material.checkbox.a a;

    public b(com.google.android.material.checkbox.a aVar) {
        this.a = aVar;
    }

    @Override // android.graphics.drawable.Animatable2.AnimationCallback
    public final void onAnimationEnd(Drawable drawable) {
        ColorStateList colorStateList = this.a.b.o;
        if (colorStateList != null) {
            drawable.setTintList(colorStateList);
        }
    }

    @Override // android.graphics.drawable.Animatable2.AnimationCallback
    public final void onAnimationStart(Drawable drawable) {
        MaterialCheckBox materialCheckBox = this.a.b;
        ColorStateList colorStateList = materialCheckBox.o;
        if (colorStateList != null) {
            drawable.setTint(colorStateList.getColorForState(materialCheckBox.s, colorStateList.getDefaultColor()));
        }
    }
}
