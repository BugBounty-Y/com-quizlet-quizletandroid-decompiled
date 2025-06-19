package com.quizlet.quizletandroid.ui.studymodes.write;

import com.quizlet.quizletandroid.databinding.C4608l;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ WriteModePromptView b;

    public /* synthetic */ f(WriteModePromptView writeModePromptView, int i) {
        this.a = i;
        this.b = writeModePromptView;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.B.requestFocus();
                break;
            default:
                WriteModeActivity writeModeActivity = (WriteModeActivity) this.b.f;
                ((C4608l) writeModeActivity.k).d.setVisibility(8);
                writeModeActivity.S();
                break;
        }
    }
}
