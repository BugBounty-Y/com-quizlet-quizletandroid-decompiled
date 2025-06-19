package com.google.firebase.perf.session.gauges;

import android.annotation.SuppressLint;
import android.content.Context;
import androidx.annotation.Keep;
import com.facebook.login.E;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3692p;
import com.google.android.gms.measurement.internal.Z;
import com.google.firebase.components.l;
import com.google.firebase.perf.config.m;
import com.google.firebase.perf.config.n;
import com.google.firebase.perf.config.p;
import com.google.firebase.perf.config.q;
import com.google.firebase.perf.session.PerfSession;
import com.google.firebase.perf.util.Timer;
import com.google.firebase.perf.v1.C3974d;
import com.google.firebase.perf.v1.i;
import com.google.firebase.perf.v1.k;
import com.google.firebase.perf.v1.o;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

@Keep
/* loaded from: classes2.dex */
public class GaugeManager {
    private static final long APPROX_NUMBER_OF_DATA_POINTS_PER_GAUGE_METRIC = 20;
    private static final long INVALID_GAUGE_COLLECTION_FREQUENCY = -1;
    private static final long TIME_TO_WAIT_BEFORE_FLUSHING_GAUGES_QUEUE_MS = 20;
    private i applicationProcessState;
    private final com.google.firebase.perf.config.a configResolver;
    private final l cpuGaugeCollector;
    private ScheduledFuture gaugeManagerDataCollectionJob;
    private final l gaugeManagerExecutor;
    private d gaugeMetadataManager;
    private final l memoryGaugeCollector;
    private String sessionId;
    private final com.google.firebase.perf.transport.f transportManager;
    private static final com.google.firebase.perf.logging.a logger = com.google.firebase.perf.logging.a.d();
    private static final GaugeManager instance = new GaugeManager();

    @SuppressLint({"ThreadPoolCreation"})
    private GaugeManager() {
        this(new l(new com.google.firebase.components.f(8)), com.google.firebase.perf.transport.f.s, com.google.firebase.perf.config.a.e(), null, new l(new com.google.firebase.components.f(9)), new l(new com.google.firebase.components.f(10)));
    }

    private static void collectGaugeMetricOnce(b bVar, f fVar, Timer timer) {
        synchronized (bVar) {
            try {
                bVar.b.schedule(new a(bVar, timer, 1), 0L, TimeUnit.MILLISECONDS);
            } catch (RejectedExecutionException e) {
                b.g.f("Unable to collect Cpu Metric: " + e.getMessage());
            }
        }
        synchronized (fVar) {
            try {
                fVar.a.schedule(new e(fVar, timer, 1), 0L, TimeUnit.MILLISECONDS);
            } catch (RejectedExecutionException e2) {
                f.f.f("Unable to collect Memory Metric: " + e2.getMessage());
            }
        }
    }

    private long getCpuGaugeCollectionFrequencyMs(i iVar) {
        n nVar;
        long jLongValue;
        m mVar;
        int iOrdinal = iVar.ordinal();
        if (iOrdinal == 1) {
            com.google.firebase.perf.config.a aVar = this.configResolver;
            aVar.getClass();
            synchronized (n.class) {
                try {
                    if (n.b == null) {
                        n.b = new n();
                    }
                    nVar = n.b;
                } finally {
                }
            }
            com.google.firebase.perf.util.d dVarJ = aVar.j(nVar);
            if (dVarJ.b() && com.google.firebase.perf.config.a.n(((Long) dVarJ.a()).longValue())) {
                jLongValue = ((Long) dVarJ.a()).longValue();
            } else {
                com.google.firebase.perf.util.d dVar = aVar.a.getLong("fpr_session_gauge_cpu_capture_frequency_fg_ms");
                if (dVar.b() && com.google.firebase.perf.config.a.n(((Long) dVar.a()).longValue())) {
                    aVar.c.d(((Long) dVar.a()).longValue(), "com.google.firebase.perf.SessionsCpuCaptureFrequencyForegroundMs");
                    jLongValue = ((Long) dVar.a()).longValue();
                } else {
                    com.google.firebase.perf.util.d dVarC = aVar.c(nVar);
                    jLongValue = (dVarC.b() && com.google.firebase.perf.config.a.n(((Long) dVarC.a()).longValue())) ? ((Long) dVarC.a()).longValue() : aVar.a.isLastFetchFailed() ? 300L : 100L;
                }
            }
        } else if (iOrdinal != 2) {
            jLongValue = -1;
        } else {
            com.google.firebase.perf.config.a aVar2 = this.configResolver;
            aVar2.getClass();
            synchronized (m.class) {
                try {
                    if (m.b == null) {
                        m.b = new m();
                    }
                    mVar = m.b;
                } finally {
                }
            }
            com.google.firebase.perf.util.d dVarJ2 = aVar2.j(mVar);
            if (dVarJ2.b() && com.google.firebase.perf.config.a.n(((Long) dVarJ2.a()).longValue())) {
                jLongValue = ((Long) dVarJ2.a()).longValue();
            } else {
                com.google.firebase.perf.util.d dVar2 = aVar2.a.getLong("fpr_session_gauge_cpu_capture_frequency_bg_ms");
                if (dVar2.b() && com.google.firebase.perf.config.a.n(((Long) dVar2.a()).longValue())) {
                    aVar2.c.d(((Long) dVar2.a()).longValue(), "com.google.firebase.perf.SessionsCpuCaptureFrequencyBackgroundMs");
                    jLongValue = ((Long) dVar2.a()).longValue();
                } else {
                    com.google.firebase.perf.util.d dVarC2 = aVar2.c(mVar);
                    jLongValue = (dVarC2.b() && com.google.firebase.perf.config.a.n(((Long) dVarC2.a()).longValue())) ? ((Long) dVarC2.a()).longValue() : 0L;
                }
            }
        }
        com.google.firebase.perf.logging.a aVar3 = b.g;
        if (jLongValue <= 0) {
            return -1L;
        }
        return jLongValue;
    }

    private com.google.firebase.perf.v1.m getGaugeMetadata() {
        com.google.firebase.perf.v1.l lVarB = com.google.firebase.perf.v1.m.B();
        int iB = AbstractC3692p.b((Z.b(5) * this.gaugeMetadataManager.c.totalMem) / 1024);
        lVarB.k();
        com.google.firebase.perf.v1.m.y((com.google.firebase.perf.v1.m) lVarB.b, iB);
        int iB2 = AbstractC3692p.b((Z.b(5) * this.gaugeMetadataManager.a.maxMemory()) / 1024);
        lVarB.k();
        com.google.firebase.perf.v1.m.w((com.google.firebase.perf.v1.m) lVarB.b, iB2);
        int iB3 = AbstractC3692p.b((Z.b(3) * this.gaugeMetadataManager.b.getMemoryClass()) / 1024);
        lVarB.k();
        com.google.firebase.perf.v1.m.x((com.google.firebase.perf.v1.m) lVarB.b, iB3);
        return (com.google.firebase.perf.v1.m) lVarB.h();
    }

    public static synchronized GaugeManager getInstance() {
        return instance;
    }

    private long getMemoryGaugeCollectionFrequencyMs(i iVar) {
        q qVar;
        long jLongValue;
        p pVar;
        int iOrdinal = iVar.ordinal();
        if (iOrdinal == 1) {
            com.google.firebase.perf.config.a aVar = this.configResolver;
            aVar.getClass();
            synchronized (q.class) {
                try {
                    if (q.b == null) {
                        q.b = new q();
                    }
                    qVar = q.b;
                } finally {
                }
            }
            com.google.firebase.perf.util.d dVarJ = aVar.j(qVar);
            if (dVarJ.b() && com.google.firebase.perf.config.a.n(((Long) dVarJ.a()).longValue())) {
                jLongValue = ((Long) dVarJ.a()).longValue();
            } else {
                com.google.firebase.perf.util.d dVar = aVar.a.getLong("fpr_session_gauge_memory_capture_frequency_fg_ms");
                if (dVar.b() && com.google.firebase.perf.config.a.n(((Long) dVar.a()).longValue())) {
                    aVar.c.d(((Long) dVar.a()).longValue(), "com.google.firebase.perf.SessionsMemoryCaptureFrequencyForegroundMs");
                    jLongValue = ((Long) dVar.a()).longValue();
                } else {
                    com.google.firebase.perf.util.d dVarC = aVar.c(qVar);
                    jLongValue = (dVarC.b() && com.google.firebase.perf.config.a.n(((Long) dVarC.a()).longValue())) ? ((Long) dVarC.a()).longValue() : aVar.a.isLastFetchFailed() ? 300L : 100L;
                }
            }
        } else if (iOrdinal != 2) {
            jLongValue = -1;
        } else {
            com.google.firebase.perf.config.a aVar2 = this.configResolver;
            aVar2.getClass();
            synchronized (p.class) {
                try {
                    if (p.b == null) {
                        p.b = new p();
                    }
                    pVar = p.b;
                } finally {
                }
            }
            com.google.firebase.perf.util.d dVarJ2 = aVar2.j(pVar);
            if (dVarJ2.b() && com.google.firebase.perf.config.a.n(((Long) dVarJ2.a()).longValue())) {
                jLongValue = ((Long) dVarJ2.a()).longValue();
            } else {
                com.google.firebase.perf.util.d dVar2 = aVar2.a.getLong("fpr_session_gauge_memory_capture_frequency_bg_ms");
                if (dVar2.b() && com.google.firebase.perf.config.a.n(((Long) dVar2.a()).longValue())) {
                    aVar2.c.d(((Long) dVar2.a()).longValue(), "com.google.firebase.perf.SessionsMemoryCaptureFrequencyBackgroundMs");
                    jLongValue = ((Long) dVar2.a()).longValue();
                } else {
                    com.google.firebase.perf.util.d dVarC2 = aVar2.c(pVar);
                    jLongValue = (dVarC2.b() && com.google.firebase.perf.config.a.n(((Long) dVarC2.a()).longValue())) ? ((Long) dVarC2.a()).longValue() : 0L;
                }
            }
        }
        com.google.firebase.perf.logging.a aVar3 = f.f;
        if (jLongValue <= 0) {
            return -1L;
        }
        return jLongValue;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ b lambda$new$0() {
        return new b();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ f lambda$new$1() {
        return new f();
    }

    private boolean startCollectingCpuMetrics(long j, Timer timer) {
        if (j == -1) {
            logger.a();
            return false;
        }
        b bVar = (b) this.cpuGaugeCollector.get();
        long j2 = bVar.d;
        if (j2 == -1 || j2 == 0 || j <= 0) {
            return true;
        }
        ScheduledFuture scheduledFuture = bVar.e;
        if (scheduledFuture == null) {
            bVar.a(j, timer);
            return true;
        }
        if (bVar.f == j) {
            return true;
        }
        if (scheduledFuture != null) {
            scheduledFuture.cancel(false);
            bVar.e = null;
            bVar.f = -1L;
        }
        bVar.a(j, timer);
        return true;
    }

    private boolean startCollectingMemoryMetrics(long j, Timer timer) {
        if (j == -1) {
            logger.a();
            return false;
        }
        f fVar = (f) this.memoryGaugeCollector.get();
        com.google.firebase.perf.logging.a aVar = f.f;
        if (j <= 0) {
            fVar.getClass();
            return true;
        }
        ScheduledFuture scheduledFuture = fVar.d;
        if (scheduledFuture == null) {
            fVar.a(j, timer);
            return true;
        }
        if (fVar.e == j) {
            return true;
        }
        if (scheduledFuture != null) {
            scheduledFuture.cancel(false);
            fVar.d = null;
            fVar.e = -1L;
        }
        fVar.a(j, timer);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: syncFlush, reason: merged with bridge method [inline-methods] and merged with bridge method [inline-methods] */
    public void lambda$stopCollectingGauges$3(String str, i iVar) {
        com.google.firebase.perf.v1.n nVarG = o.G();
        while (!((b) this.cpuGaugeCollector.get()).a.isEmpty()) {
            k kVar = (k) ((b) this.cpuGaugeCollector.get()).a.poll();
            nVarG.k();
            o.z((o) nVarG.b, kVar);
        }
        while (!((f) this.memoryGaugeCollector.get()).b.isEmpty()) {
            C3974d c3974d = (C3974d) ((f) this.memoryGaugeCollector.get()).b.poll();
            nVarG.k();
            o.x((o) nVarG.b, c3974d);
        }
        nVarG.k();
        o.w((o) nVarG.b, str);
        com.google.firebase.perf.transport.f fVar = this.transportManager;
        fVar.i.execute(new E(fVar, (o) nVarG.h(), iVar, 4));
    }

    public void initializeGaugeMetadataManager(Context context) {
        this.gaugeMetadataManager = new d(context);
    }

    public boolean logGaugeMetadata(String str, i iVar) {
        if (this.gaugeMetadataManager == null) {
            return false;
        }
        com.google.firebase.perf.v1.n nVarG = o.G();
        nVarG.k();
        o.w((o) nVarG.b, str);
        com.google.firebase.perf.v1.m gaugeMetadata = getGaugeMetadata();
        nVarG.k();
        o.y((o) nVarG.b, gaugeMetadata);
        o oVar = (o) nVarG.h();
        com.google.firebase.perf.transport.f fVar = this.transportManager;
        fVar.i.execute(new E(fVar, oVar, iVar, 4));
        return true;
    }

    public void startCollectingGauges(PerfSession perfSession, i iVar) {
        if (this.sessionId != null) {
            stopCollectingGauges();
        }
        long jStartCollectingGauges = startCollectingGauges(iVar, perfSession.b);
        if (jStartCollectingGauges == -1) {
            logger.f("Invalid gauge collection frequency. Unable to start collecting Gauges.");
            return;
        }
        String str = perfSession.a;
        this.sessionId = str;
        this.applicationProcessState = iVar;
        try {
            long j = jStartCollectingGauges * 20;
            this.gaugeManagerDataCollectionJob = ((ScheduledExecutorService) this.gaugeManagerExecutor.get()).scheduleAtFixedRate(new c(this, str, iVar, 1), j, j, TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException e) {
            logger.f("Unable to start collecting Gauges: " + e.getMessage());
        }
    }

    public void stopCollectingGauges() {
        String str = this.sessionId;
        if (str == null) {
            return;
        }
        i iVar = this.applicationProcessState;
        b bVar = (b) this.cpuGaugeCollector.get();
        ScheduledFuture scheduledFuture = bVar.e;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(false);
            bVar.e = null;
            bVar.f = -1L;
        }
        f fVar = (f) this.memoryGaugeCollector.get();
        ScheduledFuture scheduledFuture2 = fVar.d;
        if (scheduledFuture2 != null) {
            scheduledFuture2.cancel(false);
            fVar.d = null;
            fVar.e = -1L;
        }
        ScheduledFuture scheduledFuture3 = this.gaugeManagerDataCollectionJob;
        if (scheduledFuture3 != null) {
            scheduledFuture3.cancel(false);
        }
        ((ScheduledExecutorService) this.gaugeManagerExecutor.get()).schedule(new c(this, str, iVar, 0), 20L, TimeUnit.MILLISECONDS);
        this.sessionId = null;
        this.applicationProcessState = i.APPLICATION_PROCESS_STATE_UNKNOWN;
    }

    public GaugeManager(l lVar, com.google.firebase.perf.transport.f fVar, com.google.firebase.perf.config.a aVar, d dVar, l lVar2, l lVar3) {
        this.gaugeManagerDataCollectionJob = null;
        this.sessionId = null;
        this.applicationProcessState = i.APPLICATION_PROCESS_STATE_UNKNOWN;
        this.gaugeManagerExecutor = lVar;
        this.transportManager = fVar;
        this.configResolver = aVar;
        this.gaugeMetadataManager = dVar;
        this.cpuGaugeCollector = lVar2;
        this.memoryGaugeCollector = lVar3;
    }

    private long startCollectingGauges(i iVar, Timer timer) {
        long cpuGaugeCollectionFrequencyMs = getCpuGaugeCollectionFrequencyMs(iVar);
        if (!startCollectingCpuMetrics(cpuGaugeCollectionFrequencyMs, timer)) {
            cpuGaugeCollectionFrequencyMs = -1;
        }
        long memoryGaugeCollectionFrequencyMs = getMemoryGaugeCollectionFrequencyMs(iVar);
        return startCollectingMemoryMetrics(memoryGaugeCollectionFrequencyMs, timer) ? cpuGaugeCollectionFrequencyMs == -1 ? memoryGaugeCollectionFrequencyMs : Math.min(cpuGaugeCollectionFrequencyMs, memoryGaugeCollectionFrequencyMs) : cpuGaugeCollectionFrequencyMs;
    }

    public void collectGaugeMetricOnce(Timer timer) {
        collectGaugeMetricOnce((b) this.cpuGaugeCollector.get(), (f) this.memoryGaugeCollector.get(), timer);
    }
}
