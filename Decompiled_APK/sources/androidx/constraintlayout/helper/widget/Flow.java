package androidx.constraintlayout.helper.widget;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import androidx.constraintlayout.core.widgets.e;
import androidx.constraintlayout.core.widgets.h;
import androidx.constraintlayout.core.widgets.l;
import androidx.constraintlayout.widget.u;
import androidx.constraintlayout.widget.w;

/* loaded from: classes.dex */
public class Flow extends w {
    public h k;

    public Flow(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }

    @Override // androidx.constraintlayout.widget.w, androidx.constraintlayout.widget.c
    public final void h(AttributeSet attributeSet) throws IllegalAccessException, Resources.NotFoundException, IllegalArgumentException {
        super.h(attributeSet);
        this.k = new h();
        if (attributeSet != null) {
            TypedArray typedArrayObtainStyledAttributes = getContext().obtainStyledAttributes(attributeSet, u.b);
            int indexCount = typedArrayObtainStyledAttributes.getIndexCount();
            for (int i = 0; i < indexCount; i++) {
                int index = typedArrayObtainStyledAttributes.getIndex(i);
                if (index == 0) {
                    this.k.Y0 = typedArrayObtainStyledAttributes.getInt(index, 0);
                } else if (index == 1) {
                    h hVar = this.k;
                    int dimensionPixelSize = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, 0);
                    hVar.v0 = dimensionPixelSize;
                    hVar.w0 = dimensionPixelSize;
                    hVar.x0 = dimensionPixelSize;
                    hVar.y0 = dimensionPixelSize;
                } else if (index == 18) {
                    h hVar2 = this.k;
                    int dimensionPixelSize2 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, 0);
                    hVar2.x0 = dimensionPixelSize2;
                    hVar2.z0 = dimensionPixelSize2;
                    hVar2.A0 = dimensionPixelSize2;
                } else if (index == 19) {
                    this.k.y0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, 0);
                } else if (index == 2) {
                    this.k.z0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, 0);
                } else if (index == 3) {
                    this.k.v0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, 0);
                } else if (index == 4) {
                    this.k.A0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, 0);
                } else if (index == 5) {
                    this.k.w0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, 0);
                } else if (index == 54) {
                    this.k.W0 = typedArrayObtainStyledAttributes.getInt(index, 0);
                } else if (index == 44) {
                    this.k.G0 = typedArrayObtainStyledAttributes.getInt(index, 0);
                } else if (index == 53) {
                    this.k.H0 = typedArrayObtainStyledAttributes.getInt(index, 0);
                } else if (index == 38) {
                    this.k.I0 = typedArrayObtainStyledAttributes.getInt(index, 0);
                } else if (index == 46) {
                    this.k.K0 = typedArrayObtainStyledAttributes.getInt(index, 0);
                } else if (index == 40) {
                    this.k.J0 = typedArrayObtainStyledAttributes.getInt(index, 0);
                } else if (index == 48) {
                    this.k.L0 = typedArrayObtainStyledAttributes.getInt(index, 0);
                } else if (index == 42) {
                    this.k.M0 = typedArrayObtainStyledAttributes.getFloat(index, 0.5f);
                } else if (index == 37) {
                    this.k.O0 = typedArrayObtainStyledAttributes.getFloat(index, 0.5f);
                } else if (index == 45) {
                    this.k.Q0 = typedArrayObtainStyledAttributes.getFloat(index, 0.5f);
                } else if (index == 39) {
                    this.k.P0 = typedArrayObtainStyledAttributes.getFloat(index, 0.5f);
                } else if (index == 47) {
                    this.k.R0 = typedArrayObtainStyledAttributes.getFloat(index, 0.5f);
                } else if (index == 51) {
                    this.k.N0 = typedArrayObtainStyledAttributes.getFloat(index, 0.5f);
                } else if (index == 41) {
                    this.k.U0 = typedArrayObtainStyledAttributes.getInt(index, 2);
                } else if (index == 50) {
                    this.k.V0 = typedArrayObtainStyledAttributes.getInt(index, 2);
                } else if (index == 43) {
                    this.k.S0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, 0);
                } else if (index == 52) {
                    this.k.T0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, 0);
                } else if (index == 49) {
                    this.k.X0 = typedArrayObtainStyledAttributes.getInt(index, -1);
                }
            }
            typedArrayObtainStyledAttributes.recycle();
        }
        this.d = this.k;
        k();
    }

    @Override // androidx.constraintlayout.widget.c
    public final void i(e eVar, boolean z) {
        h hVar = this.k;
        int i = hVar.x0;
        if (i > 0 || hVar.y0 > 0) {
            if (z) {
                hVar.z0 = hVar.y0;
                hVar.A0 = i;
            } else {
                hVar.z0 = i;
                hVar.A0 = hVar.y0;
            }
        }
    }

    @Override // androidx.constraintlayout.widget.w
    public final void l(l lVar, int i, int i2) {
        int mode = View.MeasureSpec.getMode(i);
        int size = View.MeasureSpec.getSize(i);
        int mode2 = View.MeasureSpec.getMode(i2);
        int size2 = View.MeasureSpec.getSize(i2);
        if (lVar == null) {
            setMeasuredDimension(0, 0);
        } else {
            lVar.Y(mode, size, mode2, size2);
            setMeasuredDimension(lVar.C0, lVar.D0);
        }
    }

    @Override // androidx.constraintlayout.widget.c, android.view.View
    public final void onMeasure(int i, int i2) {
        l(this.k, i, i2);
    }

    public void setFirstHorizontalBias(float f) {
        this.k.O0 = f;
        requestLayout();
    }

    public void setFirstHorizontalStyle(int i) {
        this.k.I0 = i;
        requestLayout();
    }

    public void setFirstVerticalBias(float f) {
        this.k.P0 = f;
        requestLayout();
    }

    public void setFirstVerticalStyle(int i) {
        this.k.J0 = i;
        requestLayout();
    }

    public void setHorizontalAlign(int i) {
        this.k.U0 = i;
        requestLayout();
    }

    public void setHorizontalBias(float f) {
        this.k.M0 = f;
        requestLayout();
    }

    public void setHorizontalGap(int i) {
        this.k.S0 = i;
        requestLayout();
    }

    public void setHorizontalStyle(int i) {
        this.k.G0 = i;
        requestLayout();
    }

    public void setLastHorizontalBias(float f) {
        this.k.Q0 = f;
        requestLayout();
    }

    public void setLastHorizontalStyle(int i) {
        this.k.K0 = i;
        requestLayout();
    }

    public void setLastVerticalBias(float f) {
        this.k.R0 = f;
        requestLayout();
    }

    public void setLastVerticalStyle(int i) {
        this.k.L0 = i;
        requestLayout();
    }

    public void setMaxElementsWrap(int i) {
        this.k.X0 = i;
        requestLayout();
    }

    public void setOrientation(int i) {
        this.k.Y0 = i;
        requestLayout();
    }

    public void setPadding(int i) {
        h hVar = this.k;
        hVar.v0 = i;
        hVar.w0 = i;
        hVar.x0 = i;
        hVar.y0 = i;
        requestLayout();
    }

    public void setPaddingBottom(int i) {
        this.k.w0 = i;
        requestLayout();
    }

    public void setPaddingLeft(int i) {
        this.k.z0 = i;
        requestLayout();
    }

    public void setPaddingRight(int i) {
        this.k.A0 = i;
        requestLayout();
    }

    public void setPaddingTop(int i) {
        this.k.v0 = i;
        requestLayout();
    }

    public void setVerticalAlign(int i) {
        this.k.V0 = i;
        requestLayout();
    }

    public void setVerticalBias(float f) {
        this.k.N0 = f;
        requestLayout();
    }

    public void setVerticalGap(int i) {
        this.k.T0 = i;
        requestLayout();
    }

    public void setVerticalStyle(int i) {
        this.k.H0 = i;
        requestLayout();
    }

    public void setWrapMode(int i) {
        this.k.W0 = i;
        requestLayout();
    }

    public Flow(Context context) {
        super(context);
    }
}
