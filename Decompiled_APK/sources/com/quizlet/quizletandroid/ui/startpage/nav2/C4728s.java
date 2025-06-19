package com.quizlet.quizletandroid.ui.startpage.nav2;

import kotlin.jvm.functions.Function0;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.s, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4728s extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ OldHomeFragment b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C4728s(OldHomeFragment oldHomeFragment, int i) {
        super(0);
        this.a = i;
        this.b = oldHomeFragment;
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
            case 3:
                return this.b.requireActivity().getViewModelStore();
            case 4:
                return this.b.requireActivity().getDefaultViewModelCreationExtras();
            case 5:
                return this.b.requireActivity().getDefaultViewModelProviderFactory();
            case 6:
                return this.b.requireActivity().getViewModelStore();
            case 7:
                return this.b.requireActivity().getDefaultViewModelCreationExtras();
            case 8:
                return this.b.requireActivity().getDefaultViewModelProviderFactory();
            case 9:
                return this.b.requireActivity().getViewModelStore();
            case 10:
                return this.b.requireActivity().getDefaultViewModelCreationExtras();
            default:
                return this.b.requireActivity().getDefaultViewModelProviderFactory();
        }
    }
}
