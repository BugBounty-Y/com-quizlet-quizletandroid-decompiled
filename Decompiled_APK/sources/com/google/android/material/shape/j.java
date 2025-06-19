package com.google.android.material.shape;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.ContextThemeWrapper;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3460g4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3466h4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G4;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class j {
    public static final h m = new h(0.5f);
    public AbstractC3460g4 a = new i();
    public AbstractC3460g4 b = new i();
    public AbstractC3460g4 c = new i();
    public AbstractC3460g4 d = new i();
    public c e = new a(DefinitionKt.NO_Float_VALUE);
    public c f = new a(DefinitionKt.NO_Float_VALUE);
    public c g = new a(DefinitionKt.NO_Float_VALUE);
    public c h = new a(DefinitionKt.NO_Float_VALUE);
    public e i = new e(0);
    public e j = new e(0);
    public e k = new e(0);
    public e l = new e(0);

    public static G4 a(Context context, int i, int i2, c cVar) {
        ContextThemeWrapper contextThemeWrapper = new ContextThemeWrapper(context, i);
        if (i2 != 0) {
            contextThemeWrapper = new ContextThemeWrapper(contextThemeWrapper, i2);
        }
        TypedArray typedArrayObtainStyledAttributes = contextThemeWrapper.obtainStyledAttributes(com.google.android.material.a.K);
        try {
            int i3 = typedArrayObtainStyledAttributes.getInt(0, 0);
            int i4 = typedArrayObtainStyledAttributes.getInt(3, i3);
            int i5 = typedArrayObtainStyledAttributes.getInt(4, i3);
            int i6 = typedArrayObtainStyledAttributes.getInt(2, i3);
            int i7 = typedArrayObtainStyledAttributes.getInt(1, i3);
            c cVarD = d(typedArrayObtainStyledAttributes, 5, cVar);
            c cVarD2 = d(typedArrayObtainStyledAttributes, 8, cVarD);
            c cVarD3 = d(typedArrayObtainStyledAttributes, 9, cVarD);
            c cVarD4 = d(typedArrayObtainStyledAttributes, 7, cVarD);
            c cVarD5 = d(typedArrayObtainStyledAttributes, 6, cVarD);
            G4 g4 = new G4();
            AbstractC3460g4 abstractC3460g4A = AbstractC3466h4.a(i4);
            g4.a = abstractC3460g4A;
            G4.b(abstractC3460g4A);
            g4.e = cVarD2;
            AbstractC3460g4 abstractC3460g4A2 = AbstractC3466h4.a(i5);
            g4.b = abstractC3460g4A2;
            G4.b(abstractC3460g4A2);
            g4.f = cVarD3;
            AbstractC3460g4 abstractC3460g4A3 = AbstractC3466h4.a(i6);
            g4.c = abstractC3460g4A3;
            G4.b(abstractC3460g4A3);
            g4.g = cVarD4;
            AbstractC3460g4 abstractC3460g4A4 = AbstractC3466h4.a(i7);
            g4.d = abstractC3460g4A4;
            G4.b(abstractC3460g4A4);
            g4.h = cVarD5;
            return g4;
        } finally {
            typedArrayObtainStyledAttributes.recycle();
        }
    }

    public static G4 b(Context context, AttributeSet attributeSet, int i, int i2) {
        return c(context, attributeSet, i, i2, new a(0));
    }

    public static G4 c(Context context, AttributeSet attributeSet, int i, int i2, c cVar) {
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.google.android.material.a.C, i, i2);
        int resourceId = typedArrayObtainStyledAttributes.getResourceId(0, 0);
        int resourceId2 = typedArrayObtainStyledAttributes.getResourceId(1, 0);
        typedArrayObtainStyledAttributes.recycle();
        return a(context, resourceId, resourceId2, cVar);
    }

    public static c d(TypedArray typedArray, int i, c cVar) {
        TypedValue typedValuePeekValue = typedArray.peekValue(i);
        if (typedValuePeekValue != null) {
            int i2 = typedValuePeekValue.type;
            if (i2 == 5) {
                return new a(TypedValue.complexToDimensionPixelSize(typedValuePeekValue.data, typedArray.getResources().getDisplayMetrics()));
            }
            if (i2 == 6) {
                return new h(typedValuePeekValue.getFraction(1.0f, 1.0f));
            }
        }
        return cVar;
    }

    public final boolean e(RectF rectF) {
        boolean z = this.l.getClass().equals(e.class) && this.j.getClass().equals(e.class) && this.i.getClass().equals(e.class) && this.k.getClass().equals(e.class);
        float fA = this.e.a(rectF);
        return z && ((this.f.a(rectF) > fA ? 1 : (this.f.a(rectF) == fA ? 0 : -1)) == 0 && (this.h.a(rectF) > fA ? 1 : (this.h.a(rectF) == fA ? 0 : -1)) == 0 && (this.g.a(rectF) > fA ? 1 : (this.g.a(rectF) == fA ? 0 : -1)) == 0) && ((this.b instanceof i) && (this.a instanceof i) && (this.c instanceof i) && (this.d instanceof i));
    }

    public final G4 f() {
        G4 g4 = new G4();
        g4.a = this.a;
        g4.b = this.b;
        g4.c = this.c;
        g4.d = this.d;
        g4.e = this.e;
        g4.f = this.f;
        g4.g = this.g;
        g4.h = this.h;
        g4.i = this.i;
        g4.j = this.j;
        g4.k = this.k;
        g4.l = this.l;
        return g4;
    }
}
