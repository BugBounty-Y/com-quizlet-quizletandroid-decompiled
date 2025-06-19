package com.quizlet.background.eventlogging;

import com.quizlet.quizletandroid.ui.studymodes.match.view.MatchCardView;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModePromptView;
import com.quizlet.quizletandroid.util.b;
import timber.log.c;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements io.reactivex.rxjava3.functions.a {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    private final void a() {
    }

    @Override // io.reactivex.rxjava3.functions.a
    public final void run() {
        switch (this.a) {
            case 0:
                break;
            case 1:
                c.a.m("Promo display calculations concluded", new Object[0]);
                break;
            case 2:
                int i = MatchCardView.i;
                break;
            case 3:
                int i2 = WriteModePromptView.W;
                break;
            default:
                int i3 = b.c;
                break;
        }
    }
}
