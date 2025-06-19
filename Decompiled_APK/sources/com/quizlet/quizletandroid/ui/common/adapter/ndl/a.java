package com.quizlet.quizletandroid.ui.common.adapter.ndl;

import android.view.View;
import org.wordpress.aztec.AztecText;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements View.OnLongClickListener {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Object b;

    @Override // android.view.View.OnLongClickListener
    public final boolean onLongClick(View view) {
        switch (this.a) {
            case 0:
                ((com.quizlet.data.interactor.course.a) this.b).getClass();
                return false;
            default:
                return AztecText.b((AztecText) this.b);
        }
    }

    public /* synthetic */ a(AztecText aztecText) {
        this.b = aztecText;
    }
}
