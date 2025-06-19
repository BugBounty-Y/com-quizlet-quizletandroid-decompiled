package com.quizlet.uicommon.ui.states;

import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class a extends b {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // com.quizlet.uicommon.ui.states.b
    public final int b() {
        switch (this.a) {
            case 0:
                return R.string.unable_to_reach_quizlet_msg;
            default:
                return R.string.client_error_net_exception;
        }
    }
}
