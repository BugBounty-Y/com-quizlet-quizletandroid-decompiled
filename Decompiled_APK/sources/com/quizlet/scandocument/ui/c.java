package com.quizlet.scandocument.ui;

import com.quizlet.scandocument.model.EnumC4781a;
import kotlin.NoWhenBranchMatchedException;

/* loaded from: classes3.dex */
public final class c implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ OcrToolbarView b;

    public /* synthetic */ c(OcrToolbarView ocrToolbarView, int i) {
        this.a = i;
        this.b = ocrToolbarView;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                EnumC4781a enumC4781a = (EnumC4781a) obj;
                int i = enumC4781a == null ? -1 : b.a[enumC4781a.ordinal()];
                OcrToolbarView ocrToolbarView = this.b;
                if (i == 1) {
                    ocrToolbarView.q(EnumC4781a.a);
                    return;
                } else {
                    if (i != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    ocrToolbarView.q(EnumC4781a.b);
                    return;
                }
            default:
                this.b.B.setEnabled(((Boolean) obj).booleanValue());
                return;
        }
    }
}
