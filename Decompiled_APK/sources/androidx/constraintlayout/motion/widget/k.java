package androidx.constraintlayout.motion.widget;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;

/* loaded from: classes.dex */
public class k extends androidx.constraintlayout.widget.c implements p {
    public boolean i;
    public boolean j;
    public float k;
    public View[] l;

    public k(Context context) {
        super(context);
        this.i = false;
        this.j = false;
    }

    public float getProgress() {
        return this.k;
    }

    @Override // androidx.constraintlayout.widget.c
    public final void h(AttributeSet attributeSet) throws IllegalAccessException, Resources.NotFoundException, IllegalArgumentException {
        super.h(attributeSet);
        if (attributeSet != null) {
            TypedArray typedArrayObtainStyledAttributes = getContext().obtainStyledAttributes(attributeSet, androidx.constraintlayout.widget.u.h);
            int indexCount = typedArrayObtainStyledAttributes.getIndexCount();
            for (int i = 0; i < indexCount; i++) {
                int index = typedArrayObtainStyledAttributes.getIndex(i);
                if (index == 1) {
                    this.i = typedArrayObtainStyledAttributes.getBoolean(index, this.i);
                } else if (index == 0) {
                    this.j = typedArrayObtainStyledAttributes.getBoolean(index, this.j);
                }
            }
            typedArrayObtainStyledAttributes.recycle();
        }
    }

    public void setProgress(float f) {
        this.k = f;
        int i = 0;
        if (this.b <= 0) {
            ViewGroup viewGroup = (ViewGroup) getParent();
            int childCount = viewGroup.getChildCount();
            while (i < childCount) {
                boolean z = viewGroup.getChildAt(i) instanceof k;
                i++;
            }
            return;
        }
        ConstraintLayout constraintLayout = (ConstraintLayout) getParent();
        View[] viewArr = this.g;
        if (viewArr == null || viewArr.length != this.b) {
            this.g = new View[this.b];
        }
        for (int i2 = 0; i2 < this.b; i2++) {
            this.g[i2] = constraintLayout.a(this.a[i2]);
        }
        this.l = this.g;
        while (i < this.b) {
            View view = this.l[i];
            i++;
        }
    }
}
