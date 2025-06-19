package androidx.constraintlayout.widget;

import android.content.Context;
import android.content.res.Resources;
import android.util.AttributeSet;

/* loaded from: classes.dex */
public class Group extends c {
    public Group(Context context) {
        super(context);
    }

    @Override // androidx.constraintlayout.widget.c
    public final void f(ConstraintLayout constraintLayout) {
        e(constraintLayout);
    }

    @Override // androidx.constraintlayout.widget.c
    public final void j() {
        e eVar = (e) getLayoutParams();
        eVar.q0.S(0);
        eVar.q0.N(0);
    }

    @Override // androidx.constraintlayout.widget.c, android.view.View
    public final void onAttachedToWindow() throws IllegalAccessException, Resources.NotFoundException, IllegalArgumentException {
        super.onAttachedToWindow();
        d();
    }

    @Override // android.view.View
    public void setElevation(float f) {
        super.setElevation(f);
        d();
    }

    @Override // android.view.View
    public void setVisibility(int i) {
        super.setVisibility(i);
        d();
    }

    public Group(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }
}
