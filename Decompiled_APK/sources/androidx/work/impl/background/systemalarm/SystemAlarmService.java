package androidx.work.impl.background.systemalarm;

import android.content.Intent;
import android.os.PowerManager;
import androidx.lifecycle.M;
import androidx.work.impl.utils.k;
import androidx.work.impl.utils.l;
import androidx.work.z;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Unit;

/* loaded from: classes.dex */
public class SystemAlarmService extends M {
    public static final String d = z.e("SystemAlarmService");
    public h b;
    public boolean c;

    public final void a() {
        this.c = true;
        z.c().getClass();
        String str = k.a;
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        synchronized (l.a) {
            linkedHashMap.putAll(l.b);
            Unit unit = Unit.a;
        }
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            PowerManager.WakeLock wakeLock = (PowerManager.WakeLock) entry.getKey();
            String str2 = (String) entry.getValue();
            if (wakeLock != null && wakeLock.isHeld()) {
                z.c().f(k.a, "WakeLock held for " + str2);
            }
        }
        stopSelf();
    }

    @Override // androidx.lifecycle.M, android.app.Service
    public final void onCreate() {
        super.onCreate();
        h hVar = new h(this);
        this.b = hVar;
        if (hVar.i != null) {
            z.c().a(h.k, "A completion listener for SystemAlarmDispatcher already exists.");
        } else {
            hVar.i = this;
        }
        this.c = false;
    }

    @Override // androidx.lifecycle.M, android.app.Service
    public final void onDestroy() {
        super.onDestroy();
        this.c = true;
        h hVar = this.b;
        hVar.getClass();
        z.c().getClass();
        hVar.d.f(hVar);
        hVar.i = null;
    }

    @Override // android.app.Service
    public final int onStartCommand(Intent intent, int i, int i2) {
        super.onStartCommand(intent, i, i2);
        if (this.c) {
            z.c().d(d, "Re-initializing SystemAlarmDispatcher after a request to shut-down.");
            h hVar = this.b;
            hVar.getClass();
            z.c().getClass();
            hVar.d.f(hVar);
            hVar.i = null;
            h hVar2 = new h(this);
            this.b = hVar2;
            if (hVar2.i != null) {
                z.c().a(h.k, "A completion listener for SystemAlarmDispatcher already exists.");
            } else {
                hVar2.i = this;
            }
            this.c = false;
        }
        if (intent == null) {
            return 3;
        }
        this.b.a(i2, intent);
        return 3;
    }
}
