package com.google.android.material.animation;

import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Matrix;
import android.util.Property;
import android.widget.ImageView;
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class e extends Property {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public e() {
        super(Matrix.class, "imageMatrixProperty");
        this.b = new Matrix();
    }

    @Override // android.util.Property
    public final Object get(Object obj) {
        switch (this.a) {
            case 0:
                Matrix matrix = (Matrix) this.b;
                matrix.set(((ImageView) obj).getImageMatrix());
                return matrix;
            default:
                ExtendedFloatingActionButton extendedFloatingActionButton = (ExtendedFloatingActionButton) obj;
                return Float.valueOf(a.a(DefinitionKt.NO_Float_VALUE, 1.0f, (Color.alpha(extendedFloatingActionButton.getCurrentTextColor()) / 255.0f) / Color.alpha(extendedFloatingActionButton.F.getColorForState(extendedFloatingActionButton.getDrawableState(), ((com.google.android.material.floatingactionbutton.a) this.b).b.F.getDefaultColor()))));
        }
    }

    @Override // android.util.Property
    public final void set(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((ImageView) obj).setImageMatrix((Matrix) obj2);
                break;
            default:
                ExtendedFloatingActionButton extendedFloatingActionButton = (ExtendedFloatingActionButton) obj;
                Float f = (Float) obj2;
                int colorForState = extendedFloatingActionButton.F.getColorForState(extendedFloatingActionButton.getDrawableState(), ((com.google.android.material.floatingactionbutton.a) this.b).b.F.getDefaultColor());
                ColorStateList colorStateListValueOf = ColorStateList.valueOf(Color.argb((int) (a.a(DefinitionKt.NO_Float_VALUE, Color.alpha(colorForState) / 255.0f, f.floatValue()) * 255.0f), Color.red(colorForState), Color.green(colorForState), Color.blue(colorForState)));
                if (f.floatValue() != 1.0f) {
                    extendedFloatingActionButton.f(colorStateListValueOf);
                    break;
                } else {
                    extendedFloatingActionButton.f(extendedFloatingActionButton.F);
                    break;
                }
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(com.google.android.material.floatingactionbutton.a aVar) {
        super(Float.class, "LABEL_OPACITY_PROPERTY");
        this.b = aVar;
    }
}
