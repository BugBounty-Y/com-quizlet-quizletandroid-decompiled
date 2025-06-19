package com.quizlet.quizletandroid.ui.base.bus;

import android.content.Intent;
import com.quizlet.infra.legacysyncengine.managers.d;
import com.quizlet.infra.legacysyncengine.net.exceptions.ClientErrorNetException;
import com.quizlet.infra.legacysyncengine.net.exceptions.LoginRequiredNetException;
import com.quizlet.quizletandroid.managers.u;
import com.quizlet.remote.exceptions.NetException;
import com.quizlet.time.b;
import com.squareup.otto.i;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import timber.log.c;

/* loaded from: classes3.dex */
public final class a {
    public final d a;
    public final u b;
    public long c;

    public a(d loggedInUserManager, u logoutManager) {
        b timeProvider = b.a;
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(logoutManager, "logoutManager");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.a = loggedInUserManager;
        this.b = logoutManager;
    }

    @i
    public final void onPasswordChanged(com.quizlet.quizletandroid.ui.usersettings.a aVar) {
        this.c = System.currentTimeMillis();
    }

    @i
    public final void onRequestError(@NotNull com.quizlet.infra.legacysyncengine.events.a requestCompleteEvent) {
        Intrinsics.checkNotNullParameter(requestCompleteEvent, "requestCompleteEvent");
        com.quizlet.infra.legacysyncengine.net.request.i iVar = requestCompleteEvent.a;
        Intrinsics.checkNotNullExpressionValue(iVar, "getErrorInfo(...)");
        NetException netException = iVar.a;
        if (!(netException instanceof LoginRequiredNetException) || System.currentTimeMillis() - this.c < 30000) {
            if (netException instanceof ClientErrorNetException) {
                c.a.p(netException);
            }
        } else if (this.a.r != null) {
            c.a.q((LoginRequiredNetException) netException, "Forcing user logout", new Object[0]);
            u uVar = this.b;
            uVar.a();
            uVar.u.startActivity((Intent) uVar.i.get());
        }
    }
}
