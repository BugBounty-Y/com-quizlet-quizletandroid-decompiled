package com.google.firebase.perf.session;

import android.annotation.SuppressLint;
import android.content.Context;
import androidx.annotation.Keep;
import com.facebook.login.E;
import com.google.firebase.perf.application.c;
import com.google.firebase.perf.application.d;
import com.google.firebase.perf.session.gauges.GaugeManager;
import com.google.firebase.perf.v1.i;
import java.lang.ref.WeakReference;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

@Keep
/* loaded from: classes2.dex */
public class SessionManager extends d {

    @SuppressLint({"StaticFieldLeak"})
    private static final SessionManager instance = new SessionManager();
    private final c appStateMonitor;
    private final Set<WeakReference<a>> clients;
    private final GaugeManager gaugeManager;
    private PerfSession perfSession;
    private Future syncInitFuture;

    public SessionManager(GaugeManager gaugeManager, PerfSession perfSession, c cVar) {
        super(c.a());
        this.clients = new HashSet();
        this.gaugeManager = gaugeManager;
        this.perfSession = perfSession;
        this.appStateMonitor = cVar;
        registerForAppState();
    }

    public static SessionManager getInstance() {
        return instance;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void lambda$setApplicationContext$0(Context context, PerfSession perfSession) {
        this.gaugeManager.initializeGaugeMetadataManager(context);
        if (perfSession.c) {
            this.gaugeManager.logGaugeMetadata(perfSession.a, i.FOREGROUND);
        }
    }

    private void logGaugeMetadataIfCollectionEnabled(i iVar) {
        PerfSession perfSession = this.perfSession;
        if (perfSession.c) {
            this.gaugeManager.logGaugeMetadata(perfSession.a, iVar);
        }
    }

    private void startOrStopCollectingGauges(i iVar) {
        PerfSession perfSession = this.perfSession;
        if (perfSession.c) {
            this.gaugeManager.startCollectingGauges(perfSession, iVar);
        } else {
            this.gaugeManager.stopCollectingGauges();
        }
    }

    public Future getSyncInitFuture() {
        return this.syncInitFuture;
    }

    public void initializeGaugeCollection() {
        i iVar = i.FOREGROUND;
        logGaugeMetadataIfCollectionEnabled(iVar);
        startOrStopCollectingGauges(iVar);
    }

    @Override // com.google.firebase.perf.application.d, com.google.firebase.perf.application.b
    public void onUpdateAppState(i iVar) {
        super.onUpdateAppState(iVar);
        if (this.appStateMonitor.q) {
            return;
        }
        if (iVar == i.FOREGROUND) {
            updatePerfSession(PerfSession.c(UUID.randomUUID().toString()));
        } else if (this.perfSession.d()) {
            updatePerfSession(PerfSession.c(UUID.randomUUID().toString()));
        } else {
            startOrStopCollectingGauges(iVar);
        }
    }

    public final PerfSession perfSession() {
        return this.perfSession;
    }

    public void registerForSessionUpdates(WeakReference<a> weakReference) {
        synchronized (this.clients) {
            this.clients.add(weakReference);
        }
    }

    public void setApplicationContext(Context context) {
        this.syncInitFuture = Executors.newSingleThreadExecutor().submit(new E(this, context, this.perfSession, 3));
    }

    public void setPerfSession(PerfSession perfSession) {
        this.perfSession = perfSession;
    }

    public void stopGaugeCollectionIfSessionRunningTooLong() {
        if (this.perfSession.d()) {
            this.gaugeManager.stopCollectingGauges();
        }
    }

    public void unregisterForSessionUpdates(WeakReference<a> weakReference) {
        synchronized (this.clients) {
            this.clients.remove(weakReference);
        }
    }

    public void updatePerfSession(PerfSession perfSession) {
        if (perfSession.a == this.perfSession.a) {
            return;
        }
        this.perfSession = perfSession;
        synchronized (this.clients) {
            try {
                Iterator<WeakReference<a>> it2 = this.clients.iterator();
                while (it2.hasNext()) {
                    a aVar = it2.next().get();
                    if (aVar != null) {
                        aVar.a(perfSession);
                    } else {
                        it2.remove();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        logGaugeMetadataIfCollectionEnabled(this.appStateMonitor.o);
        startOrStopCollectingGauges(this.appStateMonitor.o);
    }

    private SessionManager() {
        this(GaugeManager.getInstance(), PerfSession.c(UUID.randomUUID().toString()), c.a());
    }
}
