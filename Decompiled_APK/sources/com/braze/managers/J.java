package com.braze.managers;

import com.braze.support.BrazeImageUtils;
import com.braze.ui.contentcards.adapters.ContentCardAdapter;
import com.braze.ui.inappmessage.DefaultInAppMessageViewWrapper;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class J implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;

    public /* synthetic */ J(int i, int i2, int i3) {
        this.a = i3;
        this.b = i;
        this.c = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return l0.a(this.b, this.c);
            case 1:
                return com.braze.requests.util.d.b(this.b, this.c);
            case 2:
                return BrazeImageUtils.getRemoteBitmap$lambda$19(this.b, this.c);
            case 3:
                return BrazeImageUtils.getDestinationHeightAndWidthPixels$lambda$23(this.b, this.c);
            case 4:
                return BrazeImageUtils.getLocalBitmap$lambda$12(this.b, this.c);
            case 5:
                return ContentCardAdapter.markOnScreenCardsAsRead$lambda$5(this.b, this.c);
            default:
                return DefaultInAppMessageViewWrapper.ViewOnLayoutChangeListenerC15282.onLayoutChange$lambda$0(this.b, this.c);
        }
    }
}
