package com.quizlet.quizletandroid.ui.setpage.terms;

import android.os.Bundle;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ TermListFragment b;

    public /* synthetic */ a(TermListFragment termListFragment, int i) {
        this.a = i;
        this.b = termListFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        TermListFragment termListFragment = this.b;
        switch (this.a) {
            case 0:
                String str = TermListFragment.H;
                androidx.lifecycle.viewmodel.c defaultViewModelCreationExtras = termListFragment.getDefaultViewModelCreationExtras();
                Intrinsics.checkNotNullExpressionValue(defaultViewModelCreationExtras, "<get-defaultViewModelCreationExtras>(...)");
                return defaultViewModelCreationExtras;
            default:
                String str2 = TermListFragment.H;
                Bundle arguments = termListFragment.getArguments();
                if (arguments != null) {
                    return Long.valueOf(arguments.getLong("setId"));
                }
                throw new IllegalStateException("We need a setId");
        }
    }
}
