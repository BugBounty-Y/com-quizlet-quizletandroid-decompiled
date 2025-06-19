package com.google.android.material.tabs;

import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.view.View;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class a extends com.google.android.material.shape.e {
    public final /* synthetic */ int b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i) {
        super(18);
        this.b = i;
    }

    @Override // com.google.android.material.shape.e
    public final void w(l lVar, View view, View view2, float f, Drawable drawable) {
        float fCos;
        float fCos2;
        switch (this.b) {
            case 0:
                RectF rectFS = com.google.android.material.shape.e.s(lVar, view);
                RectF rectFS2 = com.google.android.material.shape.e.s(lVar, view2);
                if (rectFS.left < rectFS2.left) {
                    double d = (f * 3.141592653589793d) / 2.0d;
                    fCos2 = (float) (1.0d - Math.cos(d));
                    fCos = (float) Math.sin(d);
                } else {
                    double d2 = (f * 3.141592653589793d) / 2.0d;
                    float fSin = (float) Math.sin(d2);
                    fCos = (float) (1.0d - Math.cos(d2));
                    fCos2 = fSin;
                }
                drawable.setBounds(com.google.android.material.animation.a.c((int) rectFS.left, fCos2, (int) rectFS2.left), drawable.getBounds().top, com.google.android.material.animation.a.c((int) rectFS.right, fCos, (int) rectFS2.right), drawable.getBounds().bottom);
                break;
            default:
                if (f >= 0.5f) {
                    view = view2;
                }
                RectF rectFS3 = com.google.android.material.shape.e.s(lVar, view);
                float fB = f < 0.5f ? com.google.android.material.animation.a.b(1.0f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0.5f, f) : com.google.android.material.animation.a.b(DefinitionKt.NO_Float_VALUE, 1.0f, 0.5f, 1.0f, f);
                drawable.setBounds((int) rectFS3.left, drawable.getBounds().top, (int) rectFS3.right, drawable.getBounds().bottom);
                drawable.setAlpha((int) (fB * 255.0f));
                break;
        }
    }
}
