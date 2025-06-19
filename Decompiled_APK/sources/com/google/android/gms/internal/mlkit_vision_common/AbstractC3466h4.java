package com.google.android.gms.internal.mlkit_vision_common;

import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.h4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3466h4 {
    public static final /* synthetic */ int a = 0;

    public static AbstractC3460g4 a(int i) {
        if (i != 0 && i == 1) {
            return new com.google.android.material.shape.d();
        }
        return new com.google.android.material.shape.i();
    }

    public static void b(View view, com.google.android.material.shape.g gVar) {
        com.google.android.material.elevation.a aVar = gVar.a.b;
        if (aVar == null || !aVar.a) {
            return;
        }
        float fE = DefinitionKt.NO_Float_VALUE;
        for (ViewParent parent = view.getParent(); parent instanceof View; parent = parent.getParent()) {
            WeakHashMap weakHashMap = androidx.core.view.V.a;
            fE += androidx.core.view.L.e((View) parent);
        }
        com.google.android.material.shape.f fVar = gVar.a;
        if (fVar.l != fE) {
            fVar.l = fE;
            gVar.u();
        }
    }

    public static void c(ViewGroup viewGroup) {
        Drawable background = viewGroup.getBackground();
        if (background instanceof com.google.android.material.shape.g) {
            b(viewGroup, (com.google.android.material.shape.g) background);
        }
    }
}
