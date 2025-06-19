package com.quizlet.quizletandroid;

import com.quizlet.eventlogger.events.CurrentUserEvent;
import com.quizlet.eventlogger.events.UserLogoutEvent;

/* loaded from: classes3.dex */
public final class B {
    public boolean a = false;
    public final /* synthetic */ C b;

    public B(C c) {
        this.b = c;
    }

    @com.squareup.otto.i
    public void onCurrentUserEvent(CurrentUserEvent currentUserEvent) {
        com.quizlet.data.connectivity.b bVar;
        C c = this.b;
        if (c.j != null && (bVar = c.i) != null && bVar.a && !this.a && currentUserEvent.c && currentUserEvent.a != null) {
            c.b();
        }
        c.j = currentUserEvent;
        this.a = currentUserEvent.c && currentUserEvent.a != null;
    }

    @com.squareup.otto.i
    public void onUserLogoutEvent(UserLogoutEvent userLogoutEvent) {
        C c = this.b;
        com.quizlet.data.connectivity.b bVar = c.i;
        if (bVar != null && bVar.a) {
            c.b();
        }
        c.j = null;
        this.a = false;
    }
}
