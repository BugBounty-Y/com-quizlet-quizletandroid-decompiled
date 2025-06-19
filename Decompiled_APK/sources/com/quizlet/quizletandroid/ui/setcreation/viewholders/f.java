package com.quizlet.quizletandroid.ui.setcreation.viewholders;

import android.view.View;
import com.quizlet.uicommon.ui.common.views.QuizletPlusBadge;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ g b;

    public /* synthetic */ f(g gVar, int i) {
        this.a = i;
        this.b = gVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                Boolean shouldShow = (Boolean) obj;
                Intrinsics.checkNotNullParameter(shouldShow, "shouldShow");
                if (shouldShow.booleanValue()) {
                    View view = this.b.e;
                    view.setVisibility(0);
                    view.animate().alpha(1.0f).setDuration(500L).start();
                    break;
                }
                break;
            case 1:
                Boolean shouldShowScanDocument = (Boolean) obj;
                Intrinsics.checkNotNullParameter(shouldShowScanDocument, "shouldShowScanDocument");
                this.b.d().setVisibility(shouldShowScanDocument.booleanValue() ? 0 : 8);
                break;
            default:
                Boolean it2 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                QuizletPlusBadge scanDocumentQPlusBadge = (QuizletPlusBadge) ((com.quizlet.features.infra.legacyadapter.databinding.f) this.b.b.f).e;
                Intrinsics.checkNotNullExpressionValue(scanDocumentQPlusBadge, "scanDocumentQPlusBadge");
                scanDocumentQPlusBadge.setVisibility(!it2.booleanValue() ? 0 : 8);
                break;
        }
    }
}
