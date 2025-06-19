package com.quizlet.quizletandroid.managers;

import com.quizlet.eventlogger.events.CurrentUserEvent;
import com.quizlet.eventlogger.events.UserLogoutEvent;

/* loaded from: classes3.dex */
public final class b {
    public final /* synthetic */ c a;

    public b(c cVar) {
        this.a = cVar;
    }

    @com.squareup.otto.i
    public void currentUser(CurrentUserEvent currentUserEvent) {
        c cVar = this.a;
        cVar.e = currentUserEvent;
        if (cVar.c) {
            cVar.b();
        }
    }

    @com.squareup.otto.i
    public void userLogOut(UserLogoutEvent userLogoutEvent) {
        c cVar = this.a;
        cVar.e = null;
        if (cVar.c) {
            cVar.b();
        }
    }
}
