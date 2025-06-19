package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Q5 {
    public static androidx.compose.foundation.layout.A0 a(androidx.compose.foundation.layout.z0 z0Var) {
        androidx.compose.ui.unit.k layoutDirection = androidx.compose.ui.unit.k.a;
        Intrinsics.checkNotNullParameter(z0Var, "<this>");
        Intrinsics.checkNotNullParameter(layoutDirection, "layoutDirection");
        return AbstractC0382e.e(AbstractC0382e.k(z0Var, layoutDirection), z0Var.d(), AbstractC0382e.j(z0Var, layoutDirection), DefinitionKt.NO_Float_VALUE, 8);
    }

    public static final androidx.compose.ui.unit.i b(androidx.compose.ui.geometry.c cVar) {
        return new androidx.compose.ui.unit.i(Math.round(cVar.a), Math.round(cVar.b), Math.round(cVar.c), Math.round(cVar.d));
    }

    public static androidx.compose.foundation.layout.A0 c(androidx.compose.foundation.layout.A0 withExtraBottomPadding, float f) {
        androidx.compose.ui.unit.k layoutDirection = androidx.compose.ui.unit.k.a;
        Intrinsics.checkNotNullParameter(withExtraBottomPadding, "$this$withExtraBottomPadding");
        Intrinsics.checkNotNullParameter(layoutDirection, "layoutDirection");
        return new androidx.compose.foundation.layout.A0(AbstractC0382e.k(withExtraBottomPadding, layoutDirection), withExtraBottomPadding.b, AbstractC0382e.j(withExtraBottomPadding, layoutDirection), withExtraBottomPadding.d + f);
    }
}
