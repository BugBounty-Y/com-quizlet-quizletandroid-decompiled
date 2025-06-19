package com.google.accompanist.drawablepainter;

import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0834w0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.geometry.e;
import androidx.compose.ui.graphics.AbstractC0845e;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.drawscope.d;
import androidx.compose.ui.unit.k;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes2.dex */
public final class a extends androidx.compose.ui.graphics.painter.b implements InterfaceC0834w0 {
    public final Drawable f;
    public final InterfaceC0773a0 g;
    public final InterfaceC0773a0 h;
    public final u i;

    public a(Drawable drawable) {
        Intrinsics.checkNotNullParameter(drawable, "drawable");
        this.f = drawable;
        this.g = C0776c.z(0);
        Object obj = c.a;
        this.h = C0776c.z(new e((drawable.getIntrinsicWidth() < 0 || drawable.getIntrinsicHeight() < 0) ? 9205357640488583168L : T4.a(drawable.getIntrinsicWidth(), drawable.getIntrinsicHeight())));
        this.i = l.b(new assistantMode.experiments.a(this, 3));
        if (drawable.getIntrinsicWidth() < 0 || drawable.getIntrinsicHeight() < 0) {
            return;
        }
        drawable.setBounds(0, 0, drawable.getIntrinsicWidth(), drawable.getIntrinsicHeight());
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void a() {
        b();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void b() {
        Drawable drawable = this.f;
        if (drawable instanceof Animatable) {
            ((Animatable) drawable).stop();
        }
        drawable.setVisible(false, false);
        drawable.setCallback(null);
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final boolean c(float f) {
        this.f.setAlpha(kotlin.ranges.l.c(kotlin.math.c.b(f * 255), 0, 255));
        return true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void d() {
        Drawable.Callback callback = (Drawable.Callback) this.i.getValue();
        Drawable drawable = this.f;
        drawable.setCallback(callback);
        drawable.setVisible(true, true);
        if (drawable instanceof Animatable) {
            ((Animatable) drawable).start();
        }
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final boolean e(AbstractC0874w abstractC0874w) {
        this.f.setColorFilter(abstractC0874w != null ? abstractC0874w.a : null);
        return true;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final void f(k layoutDirection) {
        int i;
        Intrinsics.checkNotNullParameter(layoutDirection, "layoutDirection");
        int iOrdinal = layoutDirection.ordinal();
        if (iOrdinal != 0) {
            i = 1;
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
        } else {
            i = 0;
        }
        this.f.setLayoutDirection(i);
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final long h() {
        return ((e) ((L0) this.h).getValue()).a;
    }

    @Override // androidx.compose.ui.graphics.painter.b
    public final void i(d dVar) {
        Intrinsics.checkNotNullParameter(dVar, "<this>");
        InterfaceC0858s interfaceC0858sO = dVar.e0().o();
        ((Number) ((L0) this.g).getValue()).intValue();
        int iB = kotlin.math.c.b(e.d(dVar.g()));
        int iB2 = kotlin.math.c.b(e.b(dVar.g()));
        Drawable drawable = this.f;
        drawable.setBounds(0, 0, iB, iB2);
        try {
            interfaceC0858sO.e();
            drawable.draw(AbstractC0845e.a(interfaceC0858sO));
        } finally {
            interfaceC0858sO.q();
        }
    }
}
