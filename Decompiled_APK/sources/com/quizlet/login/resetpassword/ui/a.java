package com.quizlet.login.resetpassword.ui;

import com.comscore.streaming.EventType;
import com.quizlet.quizletandroid.ui.startpage.nav2.OldHomeFragment;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 21:
                String str = OldHomeFragment.d1;
                break;
            case EventType.WINDOW_STATE /* 22 */:
                String str2 = OldHomeFragment.d1;
                break;
            case EventType.AUDIO /* 23 */:
                String str3 = OldHomeFragment.d1;
                break;
            case EventType.VIDEO /* 24 */:
                String str4 = OldHomeFragment.d1;
                break;
        }
        return Unit.a;
    }
}
