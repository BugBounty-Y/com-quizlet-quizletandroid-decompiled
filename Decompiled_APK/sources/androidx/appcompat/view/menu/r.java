package androidx.appcompat.view.menu;

import android.view.CollapsibleActionView;
import android.view.View;
import android.widget.FrameLayout;

/* loaded from: classes.dex */
public final class r extends FrameLayout implements androidx.appcompat.view.c {
    public final CollapsibleActionView a;

    /* JADX WARN: Multi-variable type inference failed */
    public r(View view) {
        super(view.getContext());
        this.a = (CollapsibleActionView) view;
        addView(view);
    }

    @Override // androidx.appcompat.view.c
    public final void c() {
        this.a.onActionViewExpanded();
    }

    @Override // androidx.appcompat.view.c
    public final void e() {
        this.a.onActionViewCollapsed();
    }
}
