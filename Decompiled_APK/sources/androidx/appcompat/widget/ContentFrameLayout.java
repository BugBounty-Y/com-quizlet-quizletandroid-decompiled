package androidx.appcompat.widget;

import android.content.Context;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.core.view.C1043d0;

/* loaded from: classes.dex */
public class ContentFrameLayout extends FrameLayout {
    public TypedValue a;
    public TypedValue b;
    public TypedValue c;
    public TypedValue d;
    public TypedValue e;
    public TypedValue f;
    public final Rect g;
    public InterfaceC0092j0 h;

    public ContentFrameLayout(@NonNull Context context) {
        this(context, null);
    }

    public TypedValue getFixedHeightMajor() {
        if (this.e == null) {
            this.e = new TypedValue();
        }
        return this.e;
    }

    public TypedValue getFixedHeightMinor() {
        if (this.f == null) {
            this.f = new TypedValue();
        }
        return this.f;
    }

    public TypedValue getFixedWidthMajor() {
        if (this.c == null) {
            this.c = new TypedValue();
        }
        return this.c;
    }

    public TypedValue getFixedWidthMinor() {
        if (this.d == null) {
            this.d = new TypedValue();
        }
        return this.d;
    }

    public TypedValue getMinWidthMajor() {
        if (this.a == null) {
            this.a = new TypedValue();
        }
        return this.a;
    }

    public TypedValue getMinWidthMinor() {
        if (this.b == null) {
            this.b = new TypedValue();
        }
        return this.b;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        InterfaceC0092j0 interfaceC0092j0 = this.h;
        if (interfaceC0092j0 != null) {
            interfaceC0092j0.getClass();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        C0095l c0095l;
        super.onDetachedFromWindow();
        InterfaceC0092j0 interfaceC0092j0 = this.h;
        if (interfaceC0092j0 != null) {
            androidx.appcompat.app.B b = (androidx.appcompat.app.B) ((com.airbnb.lottie.network.d) interfaceC0092j0).b;
            InterfaceC0094k0 interfaceC0094k0 = b.r;
            if (interfaceC0094k0 != null) {
                ActionBarOverlayLayout actionBarOverlayLayout = (ActionBarOverlayLayout) interfaceC0094k0;
                actionBarOverlayLayout.k();
                ActionMenuView actionMenuView = ((x1) actionBarOverlayLayout.e).a.a;
                if (actionMenuView != null && (c0095l = actionMenuView.t) != null) {
                    c0095l.f();
                    C0087h c0087h = c0095l.t;
                    if (c0087h != null && c0087h.b()) {
                        c0087h.i.dismiss();
                    }
                }
            }
            if (b.w != null) {
                b.l.getDecorView().removeCallbacks(b.x);
                if (b.w.isShowing()) {
                    try {
                        b.w.dismiss();
                    } catch (IllegalArgumentException unused) {
                    }
                }
                b.w = null;
            }
            C1043d0 c1043d0 = b.y;
            if (c1043d0 != null) {
                c1043d0.b();
            }
            androidx.appcompat.view.menu.n nVar = b.z(0).h;
            if (nVar != null) {
                nVar.c(true);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x004e  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x009d  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00d1  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00de  */
    @Override // android.widget.FrameLayout, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onMeasure(int r17, int r18) {
        /*
            Method dump skipped, instructions count: 229
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.ContentFrameLayout.onMeasure(int, int):void");
    }

    public void setAttachListener(InterfaceC0092j0 interfaceC0092j0) {
        this.h = interfaceC0092j0;
    }

    public ContentFrameLayout(@NonNull Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        this.g = new Rect();
    }
}
