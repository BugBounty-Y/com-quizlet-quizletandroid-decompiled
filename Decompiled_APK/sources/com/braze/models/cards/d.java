package com.braze.models.cards;

import com.braze.ui.contentcards.adapters.ContentCardAdapter;
import com.braze.ui.widget.BaseCardView;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class d implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Card b;

    public /* synthetic */ d(Card card, int i) {
        this.a = i;
        this.b = card;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Card.logClick$lambda$14(this.b);
            case 1:
                return Card.logClick$lambda$15(this.b);
            case 2:
                return Card.logClick$lambda$16(this.b);
            case 3:
                return Card.logImpression$lambda$8(this.b);
            case 4:
                return Card.logImpression$lambda$10(this.b);
            case 5:
                return Card.logImpression$lambda$12(this.b);
            case 6:
                return ContentCardAdapter.logImpression$lambda$8(this.b);
            case 7:
                return ContentCardAdapter.logImpression$lambda$9(this.b);
            case 8:
                return BaseCardView.handleCardClick$lambda$1(this.b);
            case 9:
                return BaseCardView.handleCardClick$lambda$2(this.b);
            case 10:
                return BaseCardView.handleCardClick$lambda$3(this.b);
            case 11:
                return BaseCardView.handleCardClick$lambda$4(this.b);
            default:
                return BaseCardView.handleCardClick$lambda$5(this.b);
        }
    }
}
