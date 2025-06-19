package com.quizlet.quizletandroid.ui.setpage.terms;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class g extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ TermListFragment b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(TermListFragment termListFragment, int i) {
        super(0);
        this.a = i;
        this.b = termListFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.requireActivity().getViewModelStore();
            case 1:
                return this.b.requireActivity().getDefaultViewModelCreationExtras();
            case 2:
                return this.b.requireActivity().getDefaultViewModelProviderFactory();
            default:
                return this.b;
        }
    }
}
