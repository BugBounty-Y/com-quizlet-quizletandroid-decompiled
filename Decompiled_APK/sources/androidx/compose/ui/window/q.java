package androidx.compose.ui.window;

import android.content.Context;
import android.view.View;
import android.view.Window;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.L0;
import androidx.compose.ui.platform.AbstractC0930a;
import androidx.compose.ui.text.C0981a;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class q extends AbstractC0930a {
    public final Window a;
    public final InterfaceC0773a0 b;
    public boolean c;
    public boolean d;

    public q(Context context, Window window) {
        super(context, null);
        this.a = window;
        this.b = C0776c.z(o.a);
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public final void Content(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1735448596);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            ((Function2) ((L0) this.b).getValue()).invoke(c0814p, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0981a(this, i, 1);
        }
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public final boolean getShouldCreateCompositionOnAttachedToWindow() {
        return this.d;
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public final void internalOnLayout$ui_release(boolean z, int i, int i2, int i3, int i4) {
        View childAt;
        super.internalOnLayout$ui_release(z, i, i2, i3, i4);
        if (this.c || (childAt = getChildAt(0)) == null) {
            return;
        }
        this.a.setLayout(childAt.getMeasuredWidth(), childAt.getMeasuredHeight());
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public final void internalOnMeasure$ui_release(int i, int i2) {
        if (this.c) {
            super.internalOnMeasure$ui_release(i, i2);
            return;
        }
        super.internalOnMeasure$ui_release(View.MeasureSpec.makeMeasureSpec(Math.round(getContext().getResources().getConfiguration().screenWidthDp * getContext().getResources().getDisplayMetrics().density), Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(Math.round(getContext().getResources().getConfiguration().screenHeightDp * getContext().getResources().getDisplayMetrics().density), Integer.MIN_VALUE));
    }
}
