package com.quizlet.eventlogger;

import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.eventlogger.events.CurrentUserEvent;
import com.quizlet.eventlogger.events.UserLogoutEvent;
import com.squareup.otto.i;

/* loaded from: classes2.dex */
public final class b {
    public final /* synthetic */ EventLogBuilder a;

    public b(EventLogBuilder eventLogBuilder) {
        this.a = eventLogBuilder;
    }

    @i
    public void handleUserChangeEvents(CurrentUserEvent currentUserEvent) {
        this.a.mHasSeenCurrentUserDetails = true;
        this.a.a = currentUserEvent;
        if (currentUserEvent.c && currentUserEvent.getCurrentUser() != null) {
            if (!this.a.mHasLoggedInBefore.booleanValue()) {
                ((UserInfoCache) this.a.mUserInfoCache).d();
            }
            this.a.mHasLoggedInBefore = Boolean.TRUE;
        }
        synchronized (this.a.mLogBufferList) {
            try {
                if (this.a.mLogBufferList.size() > 0 && this.a.k()) {
                    this.a.m();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @i
    public void handleUserLogoutEvent(UserLogoutEvent userLogoutEvent) {
        this.a.mHasSeenCurrentUserDetails = true;
        EventLogBuilder eventLogBuilder = this.a;
        eventLogBuilder.a = null;
        synchronized (eventLogBuilder.mLogBufferList) {
            try {
                if (this.a.mLogBufferList.size() > 0 && this.a.k()) {
                    this.a.m();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
