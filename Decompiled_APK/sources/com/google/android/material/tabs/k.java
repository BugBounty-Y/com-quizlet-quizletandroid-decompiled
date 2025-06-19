package com.google.android.material.tabs;

import androidx.viewpager.widget.ViewPager;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class k implements e {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ k(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void d(g gVar) {
    }

    private final void e(g gVar) {
    }

    @Override // com.google.android.material.tabs.d
    public final void a(g tab) {
        switch (this.a) {
            case 0:
                break;
            default:
                Intrinsics.checkNotNullParameter(tab, "tab");
                break;
        }
    }

    @Override // com.google.android.material.tabs.d
    public final void b(g tab) {
        switch (this.a) {
            case 0:
                ((ViewPager) this.b).setCurrentItem(tab.e);
                break;
            default:
                Intrinsics.checkNotNullParameter(tab, "tab");
                com.quizlet.explanations.solution.fragments.b bVar = ((com.quizlet.explanations.solution.recyclerview.tablayout.b) this.b).b;
                Integer num = tab.a;
                Intrinsics.e(num, "null cannot be cast to non-null type kotlin.Int");
                bVar.invoke(num);
                break;
        }
    }

    @Override // com.google.android.material.tabs.d
    public final void c(g tab) {
        switch (this.a) {
            case 0:
                break;
            default:
                Intrinsics.checkNotNullParameter(tab, "tab");
                break;
        }
    }
}
