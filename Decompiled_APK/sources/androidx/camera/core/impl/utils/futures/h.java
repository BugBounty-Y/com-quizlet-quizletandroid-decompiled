package androidx.camera.core.impl.utils.futures;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.NetworkSecurityPolicy;
import android.util.Log;
import com.facebook.internal.ServiceConnectionC1547b;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.util.A;
import com.google.android.gms.ads.internal.util.C;
import com.google.android.gms.cloudmessaging.zzt;
import com.google.android.gms.internal.ads.AbstractC2025es;
import com.google.android.gms.internal.ads.C1843ak;
import com.google.android.gms.internal.ads.C1923cd;
import com.google.android.gms.internal.ads.C2412nq;
import com.google.android.gms.internal.ads.Q7;
import com.google.android.gms.internal.ads.Tv;
import com.google.android.gms.internal.measurement.B;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3298x5;
import com.google.android.gms.internal.mlkit_vision_barcode.J7;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class h implements Runnable {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ h(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    private final void a() {
        C c = (C) this.b;
        SharedPreferences sharedPreferences = ((Context) this.c).getSharedPreferences("admob", 0);
        SharedPreferences.Editor editorEdit = sharedPreferences.edit();
        try {
            synchronized (c.a) {
                try {
                    c.f = sharedPreferences;
                    c.g = editorEdit;
                    NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted();
                    c.h = c.f.getBoolean("use_https", c.h);
                    c.u = c.f.getBoolean("content_url_opted_out", c.u);
                    c.i = c.f.getString("content_url_hashes", c.i);
                    c.k = c.f.getBoolean("gad_idless", c.k);
                    c.v = c.f.getBoolean("content_vertical_opted_out", c.v);
                    c.j = c.f.getString("content_vertical_hashes", c.j);
                    c.r = c.f.getInt("version_code", c.r);
                    if (((Boolean) Q7.g.o()).booleanValue() && r.d.c.j) {
                        c.n = new C1923cd("", 0L);
                    } else {
                        c.n = new C1923cd(c.f.getString("app_settings_json", c.n.e), c.f.getLong("app_settings_last_update_ms", c.n.f));
                    }
                    c.o = c.f.getLong("app_last_background_time_ms", c.o);
                    c.q = c.f.getInt("request_in_session_count", c.q);
                    c.p = c.f.getLong("first_ad_req_time_ms", c.p);
                    c.s = c.f.getStringSet("never_pool_slots", c.s);
                    c.w = c.f.getString("display_cutout", c.w);
                    c.B = c.f.getInt("app_measurement_npa", c.B);
                    c.C = c.f.getInt("sd_app_measure_npa", c.C);
                    c.D = c.f.getLong("sd_app_measure_npa_ts", c.D);
                    c.x = c.f.getString("inspector_info", c.x);
                    c.y = c.f.getBoolean("linked_device", c.y);
                    c.z = c.f.getString("linked_ad_unit", c.z);
                    c.A = c.f.getString("inspector_ui_storage", c.A);
                    c.l = c.f.getString("IABTCF_TCString", c.l);
                    c.m = c.f.getInt("gad_has_consent_for_cookies", c.m);
                    try {
                        c.t = new JSONObject(c.f.getString("native_advanced_settings", "{}"));
                    } catch (JSONException e) {
                        com.google.android.gms.ads.internal.util.client.i.i("Could not convert native advanced settings to json object", e);
                    }
                    c.m();
                } finally {
                }
            }
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.j.C.h.h("AdSharedPreferenceManagerImpl.initializeOnBackgroundThread", th);
            A.m();
        }
    }

    private final void b() {
        C1843ak c1843ak = ((C1843ak[]) this.c)[0];
        if (c1843ak != null) {
            C2412nq c2412nq = ((com.google.android.gms.ads.nonagon.signalgeneration.i) this.b).f;
            Tv tvE = AbstractC2025es.E(c1843ak);
            synchronized (c2412nq) {
                c2412nq.a.addFirst(tvE);
            }
        }
    }

    private final void c() {
        com.google.android.gms.cloudmessaging.i iVar = (com.google.android.gms.cloudmessaging.i) this.b;
        int i = ((com.google.android.gms.cloudmessaging.j) this.c).a;
        synchronized (iVar) {
            com.google.android.gms.cloudmessaging.j jVar = (com.google.android.gms.cloudmessaging.j) iVar.e.get(i);
            if (jVar != null) {
                Log.w("MessengerIpcClient", "Timing out request: " + i);
                iVar.e.remove(i);
                jVar.b(new zzt("Timed out waiting for response", null));
                iVar.c();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:142:0x043d  */
    /* JADX WARN: Removed duplicated region for block: B:288:0x0181 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0174  */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 1792
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.core.impl.utils.futures.h.run():void");
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return h.class.getSimpleName() + "," + ((c) this.c);
            default:
                return super.toString();
        }
    }

    public h(ServiceConnectionC1547b serviceConnectionC1547b, B b, ServiceConnectionC1547b serviceConnectionC1547b2) {
        this.a = 25;
        this.b = b;
        this.c = serviceConnectionC1547b;
    }

    public /* synthetic */ h(J7 j7, com.google.firebase.crashlytics.internal.settings.b bVar) {
        this.a = 24;
        EnumC3298x5 enumC3298x5 = EnumC3298x5.UNKNOWN_EVENT;
        this.b = j7;
        this.c = bVar;
    }

    public /* synthetic */ h(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    public h(com.google.common.util.concurrent.e futureToObserve, C5028l c5028l) {
        this.a = 2;
        Intrinsics.f(futureToObserve, "futureToObserve");
        this.b = futureToObserve;
        this.c = c5028l;
    }
}
