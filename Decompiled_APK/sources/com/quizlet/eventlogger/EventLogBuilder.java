package com.quizlet.eventlogger;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.util.DisplayMetrics;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.firebase.crashlytics.internal.common.i;
import com.quizlet.api.okhttp.interceptors.AppSessionIdProvider;
import com.quizlet.eventlogger.events.CurrentUserEvent;
import com.quizlet.eventlogger.interceptor.EventLogInterceptorManager;
import com.quizlet.eventlogger.model.AppSessionsEventLog;
import com.quizlet.eventlogger.model.EventLog;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class EventLogBuilder {
    public static final long b = System.currentTimeMillis() / 1000;
    public static int c = 0;
    private static UUID sCurrentAppSessionId;
    public CurrentUserEvent a;
    private final UUID mAndroidDeviceId;
    private final IAppSessionIdManager mAppSessionIdManager;
    private final com.quizlet.infra.contracts.session.a mAppSessionIdProvider;
    private final Context mContext;
    private final EventLogInterceptorManager mEventLogInterceptorManager;
    private final EventFileWriter mFileWriter;
    private final Executor mFilesystemExecutor;
    private Boolean mHasLoggedInBefore;
    private boolean mIsOnline;
    private boolean mIsWifi;
    private final ObjectWriter mObjectWriter;
    private final com.quizlet.data.repository.user.b mUserInfoCache;
    private final Integer versionCode;
    private final String versionName;
    private boolean mHasSeenCurrentUserDetails = false;
    private List<EventLog> mLogBufferList = Collections.synchronizedList(new ArrayList());

    @SuppressLint({"CheckResult"})
    public EventLogBuilder(Executor executor, com.squareup.otto.c cVar, Context context, EventFileWriter eventFileWriter, ObjectWriter objectWriter, com.quizlet.data.repository.user.b bVar, com.quizlet.data.connectivity.a aVar, com.quizlet.infra.contracts.session.a aVar2, String str, Integer num, IAppSessionIdManager iAppSessionIdManager, EventLogInterceptorManager eventLogInterceptorManager) throws IllegalAccessException, SecurityException, IllegalArgumentException {
        this.mFilesystemExecutor = executor;
        this.mContext = context;
        this.mFileWriter = eventFileWriter;
        this.mObjectWriter = objectWriter;
        this.mUserInfoCache = bVar;
        this.versionName = str;
        this.versionCode = num;
        this.mAndroidDeviceId = bVar.getDeviceId();
        this.mHasLoggedInBefore = Boolean.valueOf(bVar.getHasLoggedInBefore());
        this.mAppSessionIdProvider = aVar2;
        this.mAppSessionIdManager = iAppSessionIdManager;
        this.mEventLogInterceptorManager = eventLogInterceptorManager;
        cVar.d(new b(this));
        com.quizlet.remote.connectivity.a aVar3 = ((com.quizlet.remote.connectivity.b) aVar).a;
        aVar3.a.u(new com.quizlet.billing.subscriptions.a(this, 2), new com.quizlet.billing.subscriptions.c(2), io.reactivex.rxjava3.internal.functions.d.c);
    }

    public static void a(EventLogBuilder eventLogBuilder, EventLog eventLog) throws Throwable {
        eventLogBuilder.getClass();
        try {
            eventLogBuilder.mFileWriter.c(eventLogBuilder.mContext, eventLogBuilder.mObjectWriter.writeValueAsString(eventLog));
        } catch (JsonProcessingException e) {
            timber.log.c.a(e);
        }
    }

    public static /* synthetic */ void b(EventLogBuilder eventLogBuilder, com.quizlet.data.connectivity.b bVar) {
        eventLogBuilder.mIsOnline = bVar.a;
        eventLogBuilder.mIsWifi = bVar.b;
    }

    public synchronized UUID getAndLogAppSessionId() {
        UUID uuidA;
        uuidA = ((AppSessionIdProvider) this.mAppSessionIdProvider).a();
        if (!uuidA.equals(sCurrentAppSessionId)) {
            sCurrentAppSessionId = uuidA;
            l();
            this.mAppSessionIdManager.a(sCurrentAppSessionId);
        }
        return uuidA;
    }

    public final void j(EventLog eventLog) {
        AppSessionIdProvider appSessionIdProvider = (AppSessionIdProvider) this.mAppSessionIdProvider;
        appSessionIdProvider.getClass();
        appSessionIdProvider.b = new Date();
        if (k()) {
            eventLog.a(getAndLogAppSessionId(), this.mAndroidDeviceId, this.mHasLoggedInBefore, this.a);
            eventLog.b(this.mIsOnline, this.mIsWifi);
            this.mFilesystemExecutor.execute(new i(19, this, eventLog));
        } else {
            this.mLogBufferList.add(eventLog);
        }
        this.mEventLogInterceptorManager.a(eventLog);
    }

    public final boolean k() {
        if (!this.mHasSeenCurrentUserDetails) {
            return false;
        }
        CurrentUserEvent currentUserEvent = this.a;
        return (currentUserEvent == null || !currentUserEvent.c) || (currentUserEvent != null && currentUserEvent.c && currentUserEvent.getCurrentUser() != null);
    }

    public final void l() {
        DisplayMetrics displayMetrics = this.mContext.getResources().getDisplayMetrics();
        float f = displayMetrics.xdpi;
        float f2 = displayMetrics.ydpi;
        int i = displayMetrics.widthPixels;
        int i2 = displayMetrics.heightPixels;
        String versionName = this.versionName;
        int iIntValue = this.versionCode.intValue();
        AppSessionsEventLog.b.getClass();
        Intrinsics.checkNotNullParameter(versionName, "versionName");
        AppSessionsEventLog appSessionsEventLog = new AppSessionsEventLog();
        appSessionsEventLog.getPayload().setSessionRank(1);
        appSessionsEventLog.getPayload().setOsName(null);
        appSessionsEventLog.getPayload().setAppVersion(versionName);
        appSessionsEventLog.getPayload().setAppBuildNumber(String.valueOf(iIntValue));
        appSessionsEventLog.getPayload().setOsVersion(Build.VERSION.RELEASE);
        appSessionsEventLog.getPayload().setDeviceModelName(Build.MODEL);
        appSessionsEventLog.getPayload().setScreenHeight(i2);
        appSessionsEventLog.getPayload().setScreenWidth(i);
        appSessionsEventLog.getPayload().setScreenXDpi((int) f);
        appSessionsEventLog.getPayload().setScreenYDpi((int) f2);
        j(appSessionsEventLog);
    }

    public final void m() {
        synchronized (this.mLogBufferList) {
            try {
                for (EventLog eventLog : this.mLogBufferList) {
                    eventLog.a(getAndLogAppSessionId(), this.mAndroidDeviceId, this.mHasLoggedInBefore, this.a);
                    eventLog.b(this.mIsOnline, this.mIsWifi);
                    this.mFilesystemExecutor.execute(new i(19, this, eventLog));
                }
                this.mLogBufferList.clear();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void n(com.google.firebase.tracing.a aVar) {
        this.mFilesystemExecutor.execute(new c(this, aVar));
    }
}
