package com.google.firebase.perf.metrics;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.fido.fido2.api.common.i;
import com.google.firebase.crashlytics.internal.common.j;
import com.google.firebase.perf.metrics.validator.e;
import com.google.firebase.perf.session.PerfSession;
import com.google.firebase.perf.session.SessionManager;
import com.google.firebase.perf.session.gauges.GaugeManager;
import com.google.firebase.perf.transport.f;
import com.google.firebase.perf.util.Timer;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/* loaded from: classes2.dex */
public class Trace extends com.google.firebase.perf.application.d implements Parcelable, com.google.firebase.perf.session.a {

    @Keep
    public static final Parcelable.Creator<Trace> CREATOR;
    public static final com.google.firebase.perf.logging.a m = com.google.firebase.perf.logging.a.d();
    public final WeakReference a;
    public final Trace b;
    public final GaugeManager c;
    public final String d;
    public final ConcurrentHashMap e;
    public final ConcurrentHashMap f;
    public final List g;
    public final ArrayList h;
    public final f i;
    public final assistantMode.utils.studiableMetadata.b j;
    public Timer k;
    public Timer l;

    static {
        new ConcurrentHashMap();
        CREATOR = new i(26);
    }

    public Trace(String str, f fVar, assistantMode.utils.studiableMetadata.b bVar, com.google.firebase.perf.application.c cVar) {
        this(str, fVar, bVar, cVar, GaugeManager.getInstance());
    }

    public static Trace c(String str) {
        return new Trace(str, f.s, new assistantMode.utils.studiableMetadata.b(19), com.google.firebase.perf.application.c.a(), GaugeManager.getInstance());
    }

    @Override // com.google.firebase.perf.session.a
    public final void a(PerfSession perfSession) {
        if (perfSession == null) {
            m.f("Unable to add new SessionId to the Trace. Continuing without it.");
        } else {
            if (this.k == null || d()) {
                return;
            }
            this.g.add(perfSession);
        }
    }

    public final void b(String str, String str2) {
        if (d()) {
            Locale locale = Locale.ENGLISH;
            throw new IllegalArgumentException(android.support.v4.media.session.a.t(new StringBuilder("Trace '"), this.d, "' has been stopped"));
        }
        ConcurrentHashMap concurrentHashMap = this.f;
        if (concurrentHashMap.containsKey(str) || concurrentHashMap.size() < 5) {
            e.b(str, str2);
        } else {
            Locale locale2 = Locale.ENGLISH;
            throw new IllegalArgumentException("Exceeds max limit of number of attributes - 5");
        }
    }

    public final boolean d() {
        return this.l != null;
    }

    @Override // android.os.Parcelable
    @Keep
    public int describeContents() {
        return 0;
    }

    public final void finalize() throws Throwable {
        try {
            if ((this.k != null) && !d()) {
                m.g("Trace '%s' is started but not stopped when it is destructed!", this.d);
                incrementTsnsCount(1);
            }
        } finally {
            super.finalize();
        }
    }

    @Keep
    public String getAttribute(@NonNull String str) {
        return (String) this.f.get(str);
    }

    @NonNull
    @Keep
    public Map<String, String> getAttributes() {
        return new HashMap(this.f);
    }

    @Keep
    public long getLongMetric(@NonNull String str) {
        Counter counter = str != null ? (Counter) this.e.get(str.trim()) : null;
        if (counter == null) {
            return 0L;
        }
        return counter.b.get();
    }

    @Keep
    public void incrementMetric(@NonNull String str, long j) {
        String strC = e.c(str);
        com.google.firebase.perf.logging.a aVar = m;
        if (strC != null) {
            aVar.c("Cannot increment metric '%s'. Metric name is invalid.(%s)", str, strC);
            return;
        }
        boolean z = this.k != null;
        String str2 = this.d;
        if (!z) {
            aVar.g("Cannot increment metric '%s' for trace '%s' because it's not started", str, str2);
            return;
        }
        if (d()) {
            aVar.g("Cannot increment metric '%s' for trace '%s' because it's been stopped", str, str2);
            return;
        }
        String strTrim = str.trim();
        ConcurrentHashMap concurrentHashMap = this.e;
        Counter counter = (Counter) concurrentHashMap.get(strTrim);
        if (counter == null) {
            counter = new Counter(strTrim);
            concurrentHashMap.put(strTrim, counter);
        }
        AtomicLong atomicLong = counter.b;
        atomicLong.addAndGet(j);
        aVar.b("Incrementing metric '%s' to %d on trace '%s'", str, Long.valueOf(atomicLong.get()), str2);
    }

    @Keep
    public void putAttribute(@NonNull String str, @NonNull String str2) {
        boolean z;
        com.google.firebase.perf.logging.a aVar = m;
        try {
            str = str.trim();
            str2 = str2.trim();
            b(str, str2);
            aVar.b("Setting attribute '%s' to '%s' on trace '%s'", str, str2, this.d);
            z = true;
        } catch (Exception e) {
            aVar.c("Can not set attribute '%s' with value '%s' (%s)", str, str2, e.getMessage());
            z = false;
        }
        if (z) {
            this.f.put(str, str2);
        }
    }

    @Keep
    public void putMetric(@NonNull String str, long j) {
        String strC = e.c(str);
        com.google.firebase.perf.logging.a aVar = m;
        if (strC != null) {
            aVar.c("Cannot set value for metric '%s'. Metric name is invalid.(%s)", str, strC);
            return;
        }
        boolean z = this.k != null;
        String str2 = this.d;
        if (!z) {
            aVar.g("Cannot set value for metric '%s' for trace '%s' because it's not started", str, str2);
            return;
        }
        if (d()) {
            aVar.g("Cannot set value for metric '%s' for trace '%s' because it's been stopped", str, str2);
            return;
        }
        String strTrim = str.trim();
        ConcurrentHashMap concurrentHashMap = this.e;
        Counter counter = (Counter) concurrentHashMap.get(strTrim);
        if (counter == null) {
            counter = new Counter(strTrim);
            concurrentHashMap.put(strTrim, counter);
        }
        counter.b.set(j);
        aVar.b("Setting metric '%s' to '%s' on trace '%s'", str, Long.valueOf(j), str2);
    }

    @Keep
    public void removeAttribute(@NonNull String str) {
        if (!d()) {
            this.f.remove(str);
            return;
        }
        com.google.firebase.perf.logging.a aVar = m;
        if (aVar.b) {
            aVar.a.getClass();
            Log.e("FirebasePerformance", "Can't remove a attribute from a Trace that's stopped.");
        }
    }

    @Keep
    public void start() {
        String str;
        String str2;
        boolean zO = com.google.firebase.perf.config.a.e().o();
        com.google.firebase.perf.logging.a aVar = m;
        if (!zO) {
            aVar.a();
            return;
        }
        String str3 = this.d;
        if (str3 == null) {
            str = "Trace name must not be null";
        } else if (str3.length() > 100) {
            Locale locale = Locale.US;
            str = "Trace name must not exceed 100 characters";
        } else if (str3.startsWith("_")) {
            int[] iArrN = AbstractC0147y.n(6);
            int length = iArrN.length;
            int i = 0;
            while (true) {
                if (i < length) {
                    switch (iArrN[i]) {
                        case 1:
                            str2 = "_as";
                            break;
                        case 2:
                            str2 = "_astui";
                            break;
                        case 3:
                            str2 = "_astfd";
                            break;
                        case 4:
                            str2 = "_asti";
                            break;
                        case 5:
                            str2 = "_fs";
                            break;
                        case 6:
                            str2 = "_bs";
                            break;
                        default:
                            throw null;
                    }
                    if (!str2.equals(str3)) {
                        i++;
                    }
                } else if (!str3.startsWith("_st_")) {
                    str = "Trace name must not start with '_'";
                }
            }
            str = null;
        } else {
            str = null;
        }
        if (str != null) {
            aVar.c("Cannot start trace '%s'. Trace name is invalid.(%s)", str3, str);
            return;
        }
        if (this.k != null) {
            aVar.c("Trace '%s' has already started, should not start again!", str3);
            return;
        }
        this.j.getClass();
        this.k = new Timer();
        registerForAppState();
        PerfSession perfSession = SessionManager.getInstance().perfSession();
        SessionManager.getInstance().registerForSessionUpdates(this.a);
        a(perfSession);
        if (perfSession.c) {
            this.c.collectGaugeMetricOnce(perfSession.b);
        }
    }

    @Keep
    public void stop() {
        boolean z = this.k != null;
        String str = this.d;
        com.google.firebase.perf.logging.a aVar = m;
        if (!z) {
            aVar.c("Trace '%s' has not been started so unable to stop!", str);
            return;
        }
        if (d()) {
            aVar.c("Trace '%s' has already stopped, should not stop again!", str);
            return;
        }
        SessionManager.getInstance().unregisterForSessionUpdates(this.a);
        unregisterForAppState();
        this.j.getClass();
        Timer timer = new Timer();
        this.l = timer;
        if (this.b == null) {
            ArrayList arrayList = this.h;
            if (!arrayList.isEmpty()) {
                Trace trace = (Trace) android.support.v4.media.session.a.e(1, arrayList);
                if (trace.l == null) {
                    trace.l = timer;
                }
            }
            if (str.isEmpty()) {
                if (aVar.b) {
                    aVar.a.getClass();
                    Log.e("FirebasePerformance", "Trace name is empty, no log is sent to server");
                    return;
                }
                return;
            }
            this.i.c(new j(this, 1).b(), getAppState());
            if (SessionManager.getInstance().perfSession().c) {
                this.c.collectGaugeMetricOnce(SessionManager.getInstance().perfSession().b);
            }
        }
    }

    @Override // android.os.Parcelable
    @Keep
    public void writeToParcel(@NonNull Parcel parcel, int i) {
        parcel.writeParcelable(this.b, 0);
        parcel.writeString(this.d);
        parcel.writeList(this.h);
        parcel.writeMap(this.e);
        parcel.writeParcelable(this.k, 0);
        parcel.writeParcelable(this.l, 0);
        synchronized (this.g) {
            parcel.writeList(this.g);
        }
    }

    public Trace(String str, f fVar, assistantMode.utils.studiableMetadata.b bVar, com.google.firebase.perf.application.c cVar, GaugeManager gaugeManager) {
        super(cVar);
        this.a = new WeakReference(this);
        this.b = null;
        this.d = str.trim();
        this.h = new ArrayList();
        this.e = new ConcurrentHashMap();
        this.f = new ConcurrentHashMap();
        this.j = bVar;
        this.i = fVar;
        this.g = Collections.synchronizedList(new ArrayList());
        this.c = gaugeManager;
    }

    public Trace(Parcel parcel, boolean z) {
        super(z ? null : com.google.firebase.perf.application.c.a());
        this.a = new WeakReference(this);
        this.b = (Trace) parcel.readParcelable(Trace.class.getClassLoader());
        this.d = parcel.readString();
        ArrayList arrayList = new ArrayList();
        this.h = arrayList;
        parcel.readList(arrayList, Trace.class.getClassLoader());
        ConcurrentHashMap concurrentHashMap = new ConcurrentHashMap();
        this.e = concurrentHashMap;
        this.f = new ConcurrentHashMap();
        parcel.readMap(concurrentHashMap, Counter.class.getClassLoader());
        this.k = (Timer) parcel.readParcelable(Timer.class.getClassLoader());
        this.l = (Timer) parcel.readParcelable(Timer.class.getClassLoader());
        List listSynchronizedList = Collections.synchronizedList(new ArrayList());
        this.g = listSynchronizedList;
        parcel.readList(listSynchronizedList, PerfSession.class.getClassLoader());
        if (z) {
            this.i = null;
            this.j = null;
            this.c = null;
        } else {
            this.i = f.s;
            this.j = new assistantMode.utils.studiableMetadata.b(19);
            this.c = GaugeManager.getInstance();
        }
    }
}
