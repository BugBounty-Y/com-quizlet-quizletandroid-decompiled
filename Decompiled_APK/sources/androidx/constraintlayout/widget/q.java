package androidx.constraintlayout.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.HashMap;

/* loaded from: classes.dex */
public class q extends ViewGroup {
    public o a;

    public q(Context context) {
        super(context);
        super.setVisibility(8);
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateDefaultLayoutParams() {
        p pVar = new p();
        pVar.r0 = 1.0f;
        pVar.s0 = false;
        pVar.t0 = DefinitionKt.NO_Float_VALUE;
        pVar.u0 = DefinitionKt.NO_Float_VALUE;
        pVar.v0 = DefinitionKt.NO_Float_VALUE;
        pVar.w0 = DefinitionKt.NO_Float_VALUE;
        pVar.x0 = 1.0f;
        pVar.y0 = 1.0f;
        pVar.z0 = DefinitionKt.NO_Float_VALUE;
        pVar.A0 = DefinitionKt.NO_Float_VALUE;
        pVar.B0 = DefinitionKt.NO_Float_VALUE;
        pVar.C0 = DefinitionKt.NO_Float_VALUE;
        pVar.D0 = DefinitionKt.NO_Float_VALUE;
        return pVar;
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        Context context = getContext();
        p pVar = new p(context, attributeSet);
        pVar.r0 = 1.0f;
        pVar.s0 = false;
        pVar.t0 = DefinitionKt.NO_Float_VALUE;
        pVar.u0 = DefinitionKt.NO_Float_VALUE;
        pVar.v0 = DefinitionKt.NO_Float_VALUE;
        pVar.w0 = DefinitionKt.NO_Float_VALUE;
        pVar.x0 = 1.0f;
        pVar.y0 = 1.0f;
        pVar.z0 = DefinitionKt.NO_Float_VALUE;
        pVar.A0 = DefinitionKt.NO_Float_VALUE;
        pVar.B0 = DefinitionKt.NO_Float_VALUE;
        pVar.C0 = DefinitionKt.NO_Float_VALUE;
        pVar.D0 = DefinitionKt.NO_Float_VALUE;
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, u.d);
        int indexCount = typedArrayObtainStyledAttributes.getIndexCount();
        for (int i = 0; i < indexCount; i++) {
            int index = typedArrayObtainStyledAttributes.getIndex(i);
            if (index == 15) {
                pVar.r0 = typedArrayObtainStyledAttributes.getFloat(index, pVar.r0);
            } else if (index == 28) {
                pVar.t0 = typedArrayObtainStyledAttributes.getFloat(index, pVar.t0);
                pVar.s0 = true;
            } else if (index == 23) {
                pVar.v0 = typedArrayObtainStyledAttributes.getFloat(index, pVar.v0);
            } else if (index == 24) {
                pVar.w0 = typedArrayObtainStyledAttributes.getFloat(index, pVar.w0);
            } else if (index == 22) {
                pVar.u0 = typedArrayObtainStyledAttributes.getFloat(index, pVar.u0);
            } else if (index == 20) {
                pVar.x0 = typedArrayObtainStyledAttributes.getFloat(index, pVar.x0);
            } else if (index == 21) {
                pVar.y0 = typedArrayObtainStyledAttributes.getFloat(index, pVar.y0);
            } else if (index == 16) {
                pVar.z0 = typedArrayObtainStyledAttributes.getFloat(index, pVar.z0);
            } else if (index == 17) {
                pVar.A0 = typedArrayObtainStyledAttributes.getFloat(index, pVar.A0);
            } else if (index == 18) {
                pVar.B0 = typedArrayObtainStyledAttributes.getFloat(index, pVar.B0);
            } else if (index == 19) {
                pVar.C0 = typedArrayObtainStyledAttributes.getFloat(index, pVar.C0);
            } else if (index == 27) {
                pVar.D0 = typedArrayObtainStyledAttributes.getFloat(index, pVar.D0);
            }
        }
        typedArrayObtainStyledAttributes.recycle();
        return pVar;
    }

    public o getConstraintSet() {
        if (this.a == null) {
            this.a = new o();
        }
        o oVar = this.a;
        oVar.getClass();
        int childCount = getChildCount();
        HashMap map = oVar.d;
        map.clear();
        for (int i = 0; i < childCount; i++) {
            View childAt = getChildAt(i);
            p pVar = (p) childAt.getLayoutParams();
            int id = childAt.getId();
            if (oVar.c && id == -1) {
                throw new RuntimeException("All children of ConstraintLayout must have ids to use ConstraintSet");
            }
            if (!map.containsKey(Integer.valueOf(id))) {
                map.put(Integer.valueOf(id), new j());
            }
            j jVar = (j) map.get(Integer.valueOf(id));
            if (jVar != null) {
                if (childAt instanceof c) {
                    c cVar = (c) childAt;
                    jVar.c(id, pVar);
                    if (cVar instanceof a) {
                        k kVar = jVar.d;
                        kVar.i0 = 1;
                        a aVar = (a) cVar;
                        kVar.g0 = aVar.getType();
                        kVar.j0 = aVar.getReferencedIds();
                        kVar.h0 = aVar.getMargin();
                    }
                }
                jVar.c(id, pVar);
            }
        }
        return this.a;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return new e(layoutParams);
    }
}
