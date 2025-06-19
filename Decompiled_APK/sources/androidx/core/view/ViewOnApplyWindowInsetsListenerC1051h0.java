package androidx.core.view;

import android.animation.ValueAnimator;
import android.os.Build;
import android.view.View;
import android.view.WindowInsets;
import androidx.appcompat.view.menu.RunnableC0069f;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Objects;
import java.util.WeakHashMap;

/* renamed from: androidx.core.view.h0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class ViewOnApplyWindowInsetsListenerC1051h0 implements View.OnApplyWindowInsetsListener {
    public final AbstractC1047f0 a;
    public D0 b;

    public ViewOnApplyWindowInsetsListenerC1051h0(View view, AbstractC1047f0 abstractC1047f0) {
        D0 d0B;
        this.a = abstractC1047f0;
        WeakHashMap weakHashMap = V.a;
        D0 d0A = M.a(view);
        if (d0A != null) {
            int i = Build.VERSION.SDK_INT;
            d0B = (i >= 34 ? new r0(d0A) : i >= 30 ? new q0(d0A) : i >= 29 ? new p0(d0A) : new n0(d0A)).b();
        } else {
            d0B = null;
        }
        this.b = d0B;
    }

    @Override // android.view.View.OnApplyWindowInsetsListener
    public final WindowInsets onApplyWindowInsets(View view, WindowInsets windowInsets) {
        z0 z0Var;
        int i = 1;
        if (!view.isLaidOut()) {
            this.b = D0.h(view, windowInsets);
            return i0.i(view, windowInsets);
        }
        D0 d0H = D0.h(view, windowInsets);
        if (this.b == null) {
            WeakHashMap weakHashMap = V.a;
            this.b = M.a(view);
        }
        if (this.b == null) {
            this.b = d0H;
            return i0.i(view, windowInsets);
        }
        AbstractC1047f0 abstractC1047f0J = i0.j(view);
        if (abstractC1047f0J != null && Objects.equals((D0) abstractC1047f0J.b, d0H)) {
            return i0.i(view, windowInsets);
        }
        int[] iArr = new int[1];
        int[] iArr2 = new int[1];
        D0 d0 = this.b;
        int i2 = 1;
        while (true) {
            z0Var = d0H.a;
            if (i2 > 512) {
                break;
            }
            androidx.core.graphics.e eVarG = z0Var.g(i2);
            androidx.core.graphics.e eVarG2 = d0.a.g(i2);
            int i3 = eVarG.a;
            int i4 = eVarG2.a;
            int i5 = eVarG.d;
            int i6 = eVarG.c;
            int i7 = eVarG.b;
            int i8 = eVarG2.d;
            int i9 = i;
            int i10 = eVarG2.c;
            int i11 = eVarG2.b;
            int i12 = (i3 > i4 || i7 > i11 || i6 > i10 || i5 > i8) ? i9 : 0;
            if (i12 != ((i3 < i4 || i7 < i11 || i6 < i10 || i5 < i8) ? i9 : 0)) {
                if (i12 != 0) {
                    iArr[0] = iArr[0] | i2;
                } else {
                    iArr2[0] = iArr2[0] | i2;
                }
            }
            i2 <<= 1;
            i = i9;
        }
        int i13 = i;
        int i14 = iArr[0];
        int i15 = iArr2[0];
        int i16 = i14 | i15;
        if (i16 == 0) {
            this.b = d0H;
            return i0.i(view, windowInsets);
        }
        D0 d02 = this.b;
        m0 m0Var = new m0(i16, (i14 & 8) != 0 ? i0.e : (i15 & 8) != 0 ? i0.f : (i14 & 519) != 0 ? i0.g : (i15 & 519) != 0 ? i0.h : null, (i16 & 8) != 0 ? 160L : 250L);
        m0Var.a.d(DefinitionKt.NO_Float_VALUE);
        ValueAnimator duration = ValueAnimator.ofFloat(DefinitionKt.NO_Float_VALUE, 1.0f).setDuration(m0Var.a.a());
        androidx.core.graphics.e eVarG3 = z0Var.g(i16);
        androidx.core.graphics.e eVarG4 = d02.a.g(i16);
        int iMin = Math.min(eVarG3.a, eVarG4.a);
        int i17 = eVarG3.b;
        int i18 = eVarG4.b;
        int iMin2 = Math.min(i17, i18);
        int i19 = eVarG3.c;
        int i20 = eVarG4.c;
        int iMin3 = Math.min(i19, i20);
        int i21 = eVarG3.d;
        int i22 = eVarG4.d;
        androidx.work.impl.model.e eVar = new androidx.work.impl.model.e(5, androidx.core.graphics.e.b(iMin, iMin2, iMin3, Math.min(i21, i22)), androidx.core.graphics.e.b(Math.max(eVarG3.a, eVarG4.a), Math.max(i17, i18), Math.max(i19, i20), Math.max(i21, i22)));
        i0.f(view, m0Var, d0H, false);
        duration.addUpdateListener(new C1049g0(m0Var, d0H, d02, i16, view));
        duration.addListener(new C1041c0(i13, m0Var, view));
        ViewTreeObserverOnPreDrawListenerC1064v.a(view, new RunnableC0069f(1, view, m0Var, eVar, duration, false));
        this.b = d0H;
        return i0.i(view, windowInsets);
    }
}
