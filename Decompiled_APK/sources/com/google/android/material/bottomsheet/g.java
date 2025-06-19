package com.google.android.material.bottomsheet;

import android.content.res.ColorStateList;
import android.os.Build;
import android.view.View;
import android.view.Window;
import androidx.core.view.D0;
import androidx.core.view.E0;
import androidx.core.view.F0;
import androidx.core.view.G0;
import androidx.core.view.L;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_common.X3;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class g extends c {
    public final Boolean a;
    public final D0 b;
    public Window c;
    public boolean d;

    public g(D0 d0, View view) {
        ColorStateList colorStateListC;
        this.b = d0;
        com.google.android.material.shape.g gVar = BottomSheetBehavior.C(view).i;
        if (gVar != null) {
            colorStateListC = gVar.a.c;
        } else {
            WeakHashMap weakHashMap = V.a;
            colorStateListC = L.c(view);
        }
        if (colorStateListC != null) {
            this.a = Boolean.valueOf(X3.d(colorStateListC.getDefaultColor()));
            return;
        }
        ColorStateList colorStateListJ = Y3.j(view.getBackground());
        Integer numValueOf = colorStateListJ != null ? Integer.valueOf(colorStateListJ.getDefaultColor()) : null;
        if (numValueOf != null) {
            this.a = Boolean.valueOf(X3.d(numValueOf.intValue()));
        } else {
            this.a = null;
        }
    }

    @Override // com.google.android.material.bottomsheet.c
    public final void a(View view) {
        d(view);
    }

    @Override // com.google.android.material.bottomsheet.c
    public final void b(View view, float f) {
        d(view);
    }

    @Override // com.google.android.material.bottomsheet.c
    public final void c(int i, View view) {
        d(view);
    }

    public final void d(View view) {
        int top = view.getTop();
        D0 d0 = this.b;
        if (top < d0.d()) {
            Window window = this.c;
            if (window != null) {
                Boolean bool = this.a;
                boolean zBooleanValue = bool == null ? this.d : bool.booleanValue();
                com.quizlet.data.repository.school.membership.a aVar = new com.quizlet.data.repository.school.membership.a(window.getDecorView());
                int i = Build.VERSION.SDK_INT;
                (i >= 35 ? new G0(window, aVar) : i >= 30 ? new F0(window, aVar) : new E0(window, aVar)).d(zBooleanValue);
            }
            view.setPadding(view.getPaddingLeft(), d0.d() - view.getTop(), view.getPaddingRight(), view.getPaddingBottom());
            return;
        }
        if (view.getTop() != 0) {
            Window window2 = this.c;
            if (window2 != null) {
                boolean z = this.d;
                com.quizlet.data.repository.school.membership.a aVar2 = new com.quizlet.data.repository.school.membership.a(window2.getDecorView());
                int i2 = Build.VERSION.SDK_INT;
                (i2 >= 35 ? new G0(window2, aVar2) : i2 >= 30 ? new F0(window2, aVar2) : new E0(window2, aVar2)).d(z);
            }
            view.setPadding(view.getPaddingLeft(), 0, view.getPaddingRight(), view.getPaddingBottom());
        }
    }

    public final void e(Window window) {
        if (this.c == window) {
            return;
        }
        this.c = window;
        if (window != null) {
            com.quizlet.data.repository.school.membership.a aVar = new com.quizlet.data.repository.school.membership.a(window.getDecorView());
            int i = Build.VERSION.SDK_INT;
            this.d = (i >= 35 ? new G0(window, aVar) : i >= 30 ? new F0(window, aVar) : new E0(window, aVar)).b();
        }
    }
}
