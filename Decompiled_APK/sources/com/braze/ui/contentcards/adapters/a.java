package com.braze.ui.contentcards.adapters;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ ContentCardAdapter c;

    public /* synthetic */ a(int i, int i2, ContentCardAdapter contentCardAdapter) {
        this.a = i2;
        this.b = i;
        this.c = contentCardAdapter;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return ContentCardAdapter.onItemDismiss$lambda$0(this.b, this.c);
            default:
                return ContentCardAdapter.getCardAtIndex$lambda$7(this.b, this.c);
        }
    }
}
