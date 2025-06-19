package com.quizlet.quizletandroid.ui.promo.rateus;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.view.View;
import android.widget.LinearLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.n0;
import com.quizlet.quizletandroid.ui.startpage.nav2.OldHomeFragment;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int g = 0;
    public final b d;
    public final EventLogger e;
    public d f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(View view, b presenter, EventLogger eventLogger) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(presenter, "presenter");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.d = presenter;
        this.e = eventLogger;
        this.f = d.a;
        QButton viewRateusPromoPositive = ((n0) e()).c;
        Intrinsics.checkNotNullExpressionValue(viewRateusPromoPositive, "viewRateusPromoPositive");
        final int i = 0;
        viewRateusPromoPositive.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.promo.rateus.c
            public final /* synthetic */ e b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i) {
                    case 0:
                        e eVar = this.b;
                        int iOrdinal = eVar.f.ordinal();
                        EventLogger eventLogger2 = eVar.e;
                        if (iOrdinal != 0) {
                            if (iOrdinal != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            b bVar = eVar.d;
                            a aVar = (a) bVar.e.get();
                            if (aVar != null) {
                                bVar.a();
                                OldHomeFragment oldHomeFragment = (OldHomeFragment) aVar;
                                if (oldHomeFragment.isAdded()) {
                                    try {
                                        if (oldHomeFragment.r == null) {
                                            Intrinsics.m("appUtil");
                                            throw null;
                                        }
                                        oldHomeFragment.startActivity(new Intent("android.intent.action.VIEW", Uri.parse("market://details?id=com.quizlet.quizletandroid")));
                                    } catch (ActivityNotFoundException unused) {
                                        if (oldHomeFragment.r == null) {
                                            Intrinsics.m("appUtil");
                                            throw null;
                                        }
                                        oldHomeFragment.startActivity(new Intent("android.intent.action.VIEW", Uri.parse("https://play.google.com/store/apps/details?id=com.quizlet.quizletandroid")));
                                    }
                                }
                            }
                            bVar.a();
                            eventLogger2.H(1, "rate_us_rate_click");
                            return;
                        }
                        QTextView viewRateusPromoQuestion = ((n0) eVar.e()).d;
                        Intrinsics.checkNotNullExpressionValue(viewRateusPromoQuestion, "viewRateusPromoQuestion");
                        viewRateusPromoQuestion.setText(R.string.rateus_promo_rateus_question_text);
                        QButton viewRateusPromoPositive2 = ((n0) eVar.e()).c;
                        Intrinsics.checkNotNullExpressionValue(viewRateusPromoPositive2, "viewRateusPromoPositive");
                        viewRateusPromoPositive2.setText(R.string.rateus_promo_rateus_positive_text);
                        QButton viewRateusPromoNegative = ((n0) eVar.e()).b;
                        Intrinsics.checkNotNullExpressionValue(viewRateusPromoNegative, "viewRateusPromoNegative");
                        viewRateusPromoNegative.setText(R.string.rateus_promo_rateus_negative_text);
                        eVar.f = d.b;
                        eventLogger2.H(1, "rate_us_enjoy_click");
                        QTextView viewRateusPromoQuestion2 = ((n0) eVar.e()).d;
                        Intrinsics.checkNotNullExpressionValue(viewRateusPromoQuestion2, "viewRateusPromoQuestion");
                        com.quizlet.quizletandroid.util.d.a(eVar.b, viewRateusPromoQuestion2.getText());
                        QButton viewRateusPromoPositive3 = ((n0) eVar.e()).c;
                        Intrinsics.checkNotNullExpressionValue(viewRateusPromoPositive3, "viewRateusPromoPositive");
                        viewRateusPromoPositive3.requestFocus();
                        viewRateusPromoPositive3.sendAccessibilityEvent(8);
                        return;
                    default:
                        e eVar2 = this.b;
                        int iOrdinal2 = eVar2.f.ordinal();
                        b bVar2 = eVar2.d;
                        EventLogger eventLogger3 = eVar2.e;
                        if (iOrdinal2 == 0) {
                            bVar2.a();
                            eventLogger3.H(0, "rate_us_enjoy_click");
                            return;
                        } else {
                            if (iOrdinal2 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            bVar2.a();
                            eventLogger3.H(0, "rate_us_rate_click");
                            return;
                        }
                }
            }
        });
        QButton viewRateusPromoNegative = ((n0) e()).b;
        Intrinsics.checkNotNullExpressionValue(viewRateusPromoNegative, "viewRateusPromoNegative");
        final int i2 = 1;
        viewRateusPromoNegative.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.promo.rateus.c
            public final /* synthetic */ e b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i2) {
                    case 0:
                        e eVar = this.b;
                        int iOrdinal = eVar.f.ordinal();
                        EventLogger eventLogger2 = eVar.e;
                        if (iOrdinal != 0) {
                            if (iOrdinal != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            b bVar = eVar.d;
                            a aVar = (a) bVar.e.get();
                            if (aVar != null) {
                                bVar.a();
                                OldHomeFragment oldHomeFragment = (OldHomeFragment) aVar;
                                if (oldHomeFragment.isAdded()) {
                                    try {
                                        if (oldHomeFragment.r == null) {
                                            Intrinsics.m("appUtil");
                                            throw null;
                                        }
                                        oldHomeFragment.startActivity(new Intent("android.intent.action.VIEW", Uri.parse("market://details?id=com.quizlet.quizletandroid")));
                                    } catch (ActivityNotFoundException unused) {
                                        if (oldHomeFragment.r == null) {
                                            Intrinsics.m("appUtil");
                                            throw null;
                                        }
                                        oldHomeFragment.startActivity(new Intent("android.intent.action.VIEW", Uri.parse("https://play.google.com/store/apps/details?id=com.quizlet.quizletandroid")));
                                    }
                                }
                            }
                            bVar.a();
                            eventLogger2.H(1, "rate_us_rate_click");
                            return;
                        }
                        QTextView viewRateusPromoQuestion = ((n0) eVar.e()).d;
                        Intrinsics.checkNotNullExpressionValue(viewRateusPromoQuestion, "viewRateusPromoQuestion");
                        viewRateusPromoQuestion.setText(R.string.rateus_promo_rateus_question_text);
                        QButton viewRateusPromoPositive2 = ((n0) eVar.e()).c;
                        Intrinsics.checkNotNullExpressionValue(viewRateusPromoPositive2, "viewRateusPromoPositive");
                        viewRateusPromoPositive2.setText(R.string.rateus_promo_rateus_positive_text);
                        QButton viewRateusPromoNegative2 = ((n0) eVar.e()).b;
                        Intrinsics.checkNotNullExpressionValue(viewRateusPromoNegative2, "viewRateusPromoNegative");
                        viewRateusPromoNegative2.setText(R.string.rateus_promo_rateus_negative_text);
                        eVar.f = d.b;
                        eventLogger2.H(1, "rate_us_enjoy_click");
                        QTextView viewRateusPromoQuestion2 = ((n0) eVar.e()).d;
                        Intrinsics.checkNotNullExpressionValue(viewRateusPromoQuestion2, "viewRateusPromoQuestion");
                        com.quizlet.quizletandroid.util.d.a(eVar.b, viewRateusPromoQuestion2.getText());
                        QButton viewRateusPromoPositive3 = ((n0) eVar.e()).c;
                        Intrinsics.checkNotNullExpressionValue(viewRateusPromoPositive3, "viewRateusPromoPositive");
                        viewRateusPromoPositive3.requestFocus();
                        viewRateusPromoPositive3.sendAccessibilityEvent(8);
                        return;
                    default:
                        e eVar2 = this.b;
                        int iOrdinal2 = eVar2.f.ordinal();
                        b bVar2 = eVar2.d;
                        EventLogger eventLogger3 = eVar2.e;
                        if (iOrdinal2 == 0) {
                            bVar2.a();
                            eventLogger3.H(0, "rate_us_enjoy_click");
                            return;
                        } else {
                            if (iOrdinal2 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            bVar2.a();
                            eventLogger3.H(0, "rate_us_rate_click");
                            return;
                        }
                }
            }
        });
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        Void item = (Void) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        int i = R.id.view_rateus_promo_negative;
        QButton qButton = (QButton) AbstractC3375o2.c(R.id.view_rateus_promo_negative, view);
        if (qButton != null) {
            i = R.id.view_rateus_promo_positive;
            QButton qButton2 = (QButton) AbstractC3375o2.c(R.id.view_rateus_promo_positive, view);
            if (qButton2 != null) {
                i = R.id.view_rateus_promo_question;
                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.view_rateus_promo_question, view);
                if (qTextView != null) {
                    n0 n0Var = new n0((LinearLayout) view, qButton, qButton2, qTextView);
                    Intrinsics.checkNotNullExpressionValue(n0Var, "bind(...)");
                    return n0Var;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }
}
