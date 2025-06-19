package androidx.core.view;

import android.view.ScrollFeedbackProvider;
import androidx.core.widget.NestedScrollView;

/* renamed from: androidx.core.view.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1065w implements InterfaceC1066x {
    public final ScrollFeedbackProvider a;

    public C1065w(NestedScrollView nestedScrollView) {
        this.a = ScrollFeedbackProvider.createProvider(nestedScrollView);
    }

    @Override // androidx.core.view.InterfaceC1066x
    public final void d(boolean z, int i, int i2, int i3) {
        this.a.onScrollLimit(i, i2, i3, z);
    }

    @Override // androidx.core.view.InterfaceC1066x
    public final void j(int i, int i2, int i3, int i4) {
        this.a.onScrollProgress(i, i2, i3, i4);
    }
}
