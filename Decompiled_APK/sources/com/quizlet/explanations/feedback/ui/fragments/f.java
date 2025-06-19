package com.quizlet.explanations.feedback.ui.fragments;

import android.widget.RadioGroup;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;
import com.quizlet.quizletandroid.R;
import com.quizlet.scandocument.ui.OcrToolbarView;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements RadioGroup.OnCheckedChangeListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ f(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.widget.RadioGroup.OnCheckedChangeListener
    public final void onCheckedChanged(RadioGroup radioGroup, int i) {
        com.quizlet.scandocument.model.b bVar;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                String str = ReportThisContentFragment.k;
                AssemblyInputLayout otherEditText = ((com.quizlet.explanations.databinding.j) ((ReportThisContentFragment) obj).J()).d;
                Intrinsics.checkNotNullExpressionValue(otherEditText, "otherEditText");
                otherEditText.setVisibility(i != R.id.reportOptionOther ? 4 : 0);
                return;
            default:
                OcrToolbarView ocrToolbarView = (OcrToolbarView) obj;
                int iOrdinal = ocrToolbarView.q.ordinal();
                if (iOrdinal == 0) {
                    bVar = com.quizlet.scandocument.model.b.b;
                } else {
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    bVar = com.quizlet.scandocument.model.b.a;
                }
                ocrToolbarView.q = bVar;
                ocrToolbarView.v.b(bVar);
                return;
        }
    }
}
