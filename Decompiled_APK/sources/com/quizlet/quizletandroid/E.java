package com.quizlet.quizletandroid;

import android.app.NotificationManager;
import com.quizlet.eventlogger.events.UserLogoutEvent;

/* loaded from: classes3.dex */
public final class E {
    public final /* synthetic */ QuizletApplication a;

    public E(QuizletApplication quizletApplication) {
        this.a = quizletApplication;
    }

    @com.squareup.otto.i
    public void handleUserLogoutEvent(UserLogoutEvent userLogoutEvent) {
        QuizletApplication quizletApplication = this.a;
        com.quizlet.data.repository.widget.b bVar = quizletApplication.d;
        bVar.getClass();
        new io.reactivex.rxjava3.internal.operators.completable.c(new androidx.work.impl.utils.d(bVar, 11), 4).h((io.reactivex.rxjava3.core.o) bVar.c).e();
        NotificationManager notificationManager = (NotificationManager) quizletApplication.getSystemService("notification");
        if (notificationManager != null) {
            notificationManager.cancelAll();
        }
    }
}
