package com.quizlet.features.setpage;

import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class p extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ r b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ p(r rVar, int i) {
        super(0);
        this.a = i;
        this.b = rVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.getDefaultViewModelProviderFactory();
            case 1:
                return this.b.getViewModelStore();
            case 2:
                return this.b.getDefaultViewModelCreationExtras();
            case 3:
                return this.b.getDefaultViewModelProviderFactory();
            case 4:
                return this.b.getViewModelStore();
            case 5:
                return this.b.getDefaultViewModelCreationExtras();
            case 6:
                return this.b.getDefaultViewModelProviderFactory();
            case 7:
                return this.b.getViewModelStore();
            case 8:
                return this.b.getDefaultViewModelCreationExtras();
            case 9:
                return this.b.getDefaultViewModelProviderFactory();
            case 10:
                return this.b.getViewModelStore();
            case 11:
                return this.b.getDefaultViewModelCreationExtras();
            case 12:
                return this.b.getDefaultViewModelProviderFactory();
            case 13:
                return this.b.getViewModelStore();
            case 14:
                return this.b.getDefaultViewModelCreationExtras();
            case 15:
                return this.b.getDefaultViewModelProviderFactory();
            case 16:
                return this.b.getViewModelStore();
            default:
                return this.b.getDefaultViewModelCreationExtras();
        }
    }
}
