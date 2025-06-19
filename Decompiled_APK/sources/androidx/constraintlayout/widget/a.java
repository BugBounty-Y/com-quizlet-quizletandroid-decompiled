package androidx.constraintlayout.widget;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.util.AttributeSet;

/* loaded from: classes.dex */
public class a extends c {
    public int i;
    public int j;
    public androidx.constraintlayout.core.widgets.a k;

    public a(Context context) {
        super(context);
        super.setVisibility(8);
    }

    public boolean getAllowsGoneWidget() {
        return this.k.w0;
    }

    public int getMargin() {
        return this.k.x0;
    }

    public int getType() {
        return this.i;
    }

    @Override // androidx.constraintlayout.widget.c
    public final void h(AttributeSet attributeSet) throws IllegalAccessException, Resources.NotFoundException, IllegalArgumentException {
        super.h(attributeSet);
        this.k = new androidx.constraintlayout.core.widgets.a();
        if (attributeSet != null) {
            TypedArray typedArrayObtainStyledAttributes = getContext().obtainStyledAttributes(attributeSet, u.b);
            int indexCount = typedArrayObtainStyledAttributes.getIndexCount();
            for (int i = 0; i < indexCount; i++) {
                int index = typedArrayObtainStyledAttributes.getIndex(i);
                if (index == 26) {
                    setType(typedArrayObtainStyledAttributes.getInt(index, 0));
                } else if (index == 25) {
                    this.k.w0 = typedArrayObtainStyledAttributes.getBoolean(index, true);
                } else if (index == 27) {
                    this.k.x0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, 0);
                }
            }
            typedArrayObtainStyledAttributes.recycle();
        }
        this.d = this.k;
        k();
    }

    @Override // androidx.constraintlayout.widget.c
    public final void i(androidx.constraintlayout.core.widgets.e eVar, boolean z) {
        this.j = this.i;
        if (z) {
            int i = this.i;
            if (i == 5) {
                this.j = 1;
            } else if (i == 6) {
                this.j = 0;
            }
        } else {
            int i2 = this.i;
            if (i2 == 5) {
                this.j = 0;
            } else if (i2 == 6) {
                this.j = 1;
            }
        }
        if (eVar instanceof androidx.constraintlayout.core.widgets.a) {
            ((androidx.constraintlayout.core.widgets.a) eVar).v0 = this.j;
        }
    }

    public void setAllowsGoneWidget(boolean z) {
        this.k.w0 = z;
    }

    public void setDpMargin(int i) {
        this.k.x0 = (int) ((i * getResources().getDisplayMetrics().density) + 0.5f);
    }

    public void setMargin(int i) {
        this.k.x0 = i;
    }

    public void setType(int i) {
        this.i = i;
    }
}
