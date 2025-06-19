package com.quizlet.login.intro.ui;

import com.comscore.streaming.EventType;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class k implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    public /* synthetic */ k(int i, Function1 function1) {
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(com.quizlet.login.intro.data.f.a);
                break;
            case 1:
                this.b.invoke(com.quizlet.login.intro.data.e.a);
                break;
            case 2:
                this.b.invoke(com.quizlet.login.login.data.b.a);
                break;
            case 3:
                this.b.invoke(com.quizlet.login.login.data.b.a);
                break;
            case 4:
                this.b.invoke(com.quizlet.login.login.data.a.a);
                break;
            case 5:
                this.b.invoke(com.quizlet.login.login.data.d.a);
                break;
            case 6:
                this.b.invoke(com.quizlet.login.login.data.c.a);
                break;
            case 7:
                this.b.invoke(com.quizlet.login.login.data.f.a);
                break;
            case 8:
                this.b.invoke(com.quizlet.login.parentemail.data.a.a);
                break;
            case 9:
                this.b.invoke(com.quizlet.login.parentemail.data.e.a);
                break;
            case 10:
                this.b.invoke(com.quizlet.login.parentemail.data.d.a);
                break;
            case 11:
                this.b.invoke(com.quizlet.login.resetpassword.data.a.a);
                break;
            case 12:
                this.b.invoke(Boolean.TRUE);
                break;
            case 13:
                this.b.invoke(Boolean.FALSE);
                break;
            case 14:
                this.b.invoke(com.quizlet.login.signup.data.a.a);
                break;
            case 15:
                this.b.invoke(com.quizlet.login.signup.data.g.a);
                break;
            case 16:
                this.b.invoke(com.quizlet.login.signup.data.f.a);
                break;
            case 17:
                this.b.invoke(com.quizlet.login.signup.data.b.a);
                break;
            case 18:
                this.b.invoke("");
                break;
            case 19:
                this.b.invoke(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.a.a);
                break;
            case 20:
                this.b.invoke(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.a.a);
                break;
            case 21:
                this.b.invoke(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.c.a);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                this.b.invoke(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.b.a);
                break;
            case EventType.AUDIO /* 23 */:
                this.b.invoke(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.c.a);
                break;
            case EventType.VIDEO /* 24 */:
                this.b.invoke(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.b.a);
                break;
            case EventType.SUBS /* 25 */:
                this.b.invoke(com.quizlet.report.data.e.a);
                break;
            case EventType.CDN /* 26 */:
                this.b.invoke(com.quizlet.report.data.g.a);
                break;
            default:
                this.b.invoke(com.quizlet.report.data.e.a);
                break;
        }
        return Unit.a;
    }
}
