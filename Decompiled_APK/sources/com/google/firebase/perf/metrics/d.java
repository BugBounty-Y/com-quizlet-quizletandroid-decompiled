package com.google.firebase.perf.metrics;

import androidx.recyclerview.widget.C1372j;
import com.facebook.login.E;
import com.google.firebase.perf.network.g;
import com.google.firebase.perf.session.PerfSession;
import com.google.firebase.perf.session.SessionManager;
import com.google.firebase.perf.session.gauges.GaugeManager;
import com.google.firebase.perf.transport.f;
import com.google.firebase.perf.v1.p;
import com.google.firebase.perf.v1.r;
import com.google.firebase.perf.v1.t;
import com.google.firebase.perf.v1.z;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.o;
import okhttp3.s;

/* loaded from: classes2.dex */
public final class d extends com.google.firebase.perf.application.d implements com.google.firebase.perf.session.a {
    public static final com.google.firebase.perf.logging.a h = com.google.firebase.perf.logging.a.d();
    public final List a;
    public final GaugeManager b;
    public final f c;
    public final p d;
    public final WeakReference e;
    public String f;
    public boolean g;

    /* JADX WARN: Illegal instructions before constructor call */
    public d(f fVar) {
        com.google.firebase.perf.application.c cVarA = com.google.firebase.perf.application.c.a();
        GaugeManager gaugeManager = GaugeManager.getInstance();
        super(cVarA);
        this.d = t.c0();
        this.e = new WeakReference(this);
        this.c = fVar;
        this.b = gaugeManager;
        this.a = Collections.synchronizedList(new ArrayList());
        registerForAppState();
    }

    @Override // com.google.firebase.perf.session.a
    public final void a(PerfSession perfSession) {
        if (perfSession == null) {
            h.f("Unable to add new SessionId to the Network Trace. Continuing without it.");
            return;
        }
        p pVar = this.d;
        if (!((t) pVar.b).U() || ((t) pVar.b).a0()) {
            return;
        }
        this.a.add(perfSession);
    }

    public final void b() {
        List listUnmodifiableList;
        SessionManager.getInstance().unregisterForSessionUpdates(this.e);
        unregisterForAppState();
        synchronized (this.a) {
            try {
                ArrayList arrayList = new ArrayList();
                for (PerfSession perfSession : this.a) {
                    if (perfSession != null) {
                        arrayList.add(perfSession);
                    }
                }
                listUnmodifiableList = Collections.unmodifiableList(arrayList);
            } catch (Throwable th) {
                throw th;
            }
        }
        z[] zVarArrB = PerfSession.b(listUnmodifiableList);
        if (zVarArrB != null) {
            p pVar = this.d;
            List listAsList = Arrays.asList(zVarArrB);
            pVar.k();
            t.F((t) pVar.b, listAsList);
        }
        t tVar = (t) this.d.h();
        String str = this.f;
        if (str == null) {
            Pattern pattern = g.a;
        } else if (g.a.matcher(str).matches()) {
            h.a();
            return;
        }
        if (this.g) {
            return;
        }
        f fVar = this.c;
        fVar.i.execute(new E(fVar, tVar, getAppState(), 6));
        this.g = true;
    }

    public final void c(String str) {
        r rVar;
        if (str != null) {
            String upperCase = str.toUpperCase();
            upperCase.getClass();
            switch (upperCase) {
                case "OPTIONS":
                    rVar = r.OPTIONS;
                    break;
                case "GET":
                    rVar = r.GET;
                    break;
                case "PUT":
                    rVar = r.PUT;
                    break;
                case "HEAD":
                    rVar = r.HEAD;
                    break;
                case "POST":
                    rVar = r.POST;
                    break;
                case "PATCH":
                    rVar = r.PATCH;
                    break;
                case "TRACE":
                    rVar = r.TRACE;
                    break;
                case "CONNECT":
                    rVar = r.CONNECT;
                    break;
                case "DELETE":
                    rVar = r.DELETE;
                    break;
                default:
                    rVar = r.HTTP_METHOD_UNKNOWN;
                    break;
            }
            p pVar = this.d;
            pVar.k();
            t.G((t) pVar.b, rVar);
        }
    }

    public final void d(int i) {
        p pVar = this.d;
        pVar.k();
        t.y((t) pVar.b, i);
    }

    public final void f(long j) {
        p pVar = this.d;
        pVar.k();
        t.H((t) pVar.b, j);
    }

    public final void g(long j) {
        PerfSession perfSession = SessionManager.getInstance().perfSession();
        SessionManager.getInstance().registerForSessionUpdates(this.e);
        p pVar = this.d;
        pVar.k();
        t.B((t) pVar.b, j);
        a(perfSession);
        if (perfSession.c) {
            this.b.collectGaugeMetricOnce(perfSession.b);
        }
    }

    public final void h(String str) {
        p pVar = this.d;
        if (str == null) {
            pVar.k();
            t.A((t) pVar.b);
            return;
        }
        if (str.length() <= 128) {
            for (int i = 0; i < str.length(); i++) {
                char cCharAt = str.charAt(i);
                if (cCharAt > 31 && cCharAt <= 127) {
                }
            }
            pVar.k();
            t.z((t) pVar.b, str);
            return;
        }
        h.f("The content type of the response is not a valid content-type:".concat(str));
    }

    public final void i(long j) {
        p pVar = this.d;
        pVar.k();
        t.I((t) pVar.b, j);
    }

    public final void j(long j) {
        p pVar = this.d;
        pVar.k();
        t.E((t) pVar.b, j);
        if (SessionManager.getInstance().perfSession().c) {
            this.b.collectGaugeMetricOnce(SessionManager.getInstance().perfSession().b);
        }
    }

    public final void l(String str) {
        s sVarD;
        int iLastIndexOf;
        if (str != null) {
            Intrinsics.checkNotNullParameter(str, "<this>");
            s sVarD2 = null;
            try {
                Intrinsics.checkNotNullParameter(str, "<this>");
                C1372j c1372j = new C1372j();
                c1372j.l(null, str);
                sVarD = c1372j.d();
            } catch (IllegalArgumentException unused) {
                sVarD = null;
            }
            if (sVarD != null) {
                C1372j c1372jF = sVarD.f();
                Intrinsics.checkNotNullParameter("", "username");
                c1372jF.f = o.b(0, 0, 251, "", " \"':;<=>@[]^`{}|/\\?#", false);
                Intrinsics.checkNotNullParameter("", DBStudySetFields.Names.PASSWORD);
                c1372jF.g = o.b(0, 0, 251, "", " \"':;<=>@[]^`{}|/\\?#", false);
                c1372jF.d = null;
                c1372jF.i = null;
                str = c1372jF.toString();
            }
            if (str.length() > 2000) {
                if (str.charAt(2000) == '/') {
                    str = str.substring(0, 2000);
                } else {
                    Intrinsics.checkNotNullParameter(str, "<this>");
                    try {
                        Intrinsics.checkNotNullParameter(str, "<this>");
                        C1372j c1372j2 = new C1372j();
                        c1372j2.l(null, str);
                        sVarD2 = c1372j2.d();
                    } catch (IllegalArgumentException unused2) {
                    }
                    str = (sVarD2 != null && sVarD2.b().lastIndexOf(47) >= 0 && (iLastIndexOf = str.lastIndexOf(47, 1999)) >= 0) ? str.substring(0, iLastIndexOf) : str.substring(0, 2000);
                }
            }
            p pVar = this.d;
            pVar.k();
            t.w((t) pVar.b, str);
        }
    }
}
