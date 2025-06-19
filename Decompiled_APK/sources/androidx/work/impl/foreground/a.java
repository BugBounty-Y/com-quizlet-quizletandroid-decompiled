package androidx.work.impl.foreground;

import android.app.Notification;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import androidx.work.C1442p;
import androidx.work.impl.InterfaceC1430b;
import androidx.work.impl.constraints.b;
import androidx.work.impl.constraints.j;
import androidx.work.impl.constraints.m;
import androidx.work.impl.model.q;
import androidx.work.impl.r;
import androidx.work.impl.utils.taskexecutor.c;
import androidx.work.z;
import com.google.android.gms.internal.mlkit_vision_camera.A2;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class a implements j, InterfaceC1430b {
    public static final String j = z.e("SystemFgDispatcher");
    public final r a;
    public final c b;
    public final Object c = new Object();
    public androidx.work.impl.model.j d;
    public final LinkedHashMap e;
    public final HashMap f;
    public final HashMap g;
    public final m h;
    public SystemForegroundService i;

    public a(Context context) {
        r rVarH = r.h(context);
        this.a = rVarH;
        this.b = rVarH.d;
        this.d = null;
        this.e = new LinkedHashMap();
        this.g = new HashMap();
        this.f = new HashMap();
        this.h = new m(rVarH.j);
        rVarH.f.a(this);
    }

    public static Intent a(Context context, androidx.work.impl.model.j jVar, C1442p c1442p) {
        Intent intent = new Intent(context, (Class<?>) SystemForegroundService.class);
        intent.setAction("ACTION_START_FOREGROUND");
        intent.putExtra("KEY_WORKSPEC_ID", jVar.a);
        intent.putExtra("KEY_GENERATION", jVar.b);
        intent.putExtra("KEY_NOTIFICATION_ID", c1442p.a);
        intent.putExtra("KEY_FOREGROUND_SERVICE_TYPE", c1442p.b);
        intent.putExtra("KEY_NOTIFICATION", c1442p.c);
        return intent;
    }

    @Override // androidx.work.impl.InterfaceC1430b
    public final void b(androidx.work.impl.model.j jVar, boolean z) {
        Map.Entry entry;
        synchronized (this.c) {
            try {
                InterfaceC5025j0 interfaceC5025j0 = ((q) this.f.remove(jVar)) != null ? (InterfaceC5025j0) this.g.remove(jVar) : null;
                if (interfaceC5025j0 != null) {
                    interfaceC5025j0.j(null);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        C1442p c1442p = (C1442p) this.e.remove(jVar);
        if (jVar.equals(this.d)) {
            if (this.e.size() > 0) {
                Iterator it2 = this.e.entrySet().iterator();
                Object next = it2.next();
                while (true) {
                    entry = (Map.Entry) next;
                    if (!it2.hasNext()) {
                        break;
                    } else {
                        next = it2.next();
                    }
                }
                this.d = (androidx.work.impl.model.j) entry.getKey();
                if (this.i != null) {
                    C1442p c1442p2 = (C1442p) entry.getValue();
                    SystemForegroundService systemForegroundService = this.i;
                    int i = c1442p2.a;
                    int i2 = c1442p2.b;
                    Notification notification = c1442p2.c;
                    systemForegroundService.getClass();
                    int i3 = Build.VERSION.SDK_INT;
                    if (i3 >= 31) {
                        androidx.core.graphics.c.f(systemForegroundService, i, notification, i2);
                    } else if (i3 >= 29) {
                        androidx.core.graphics.c.e(systemForegroundService, i, notification, i2);
                    } else {
                        systemForegroundService.startForeground(i, notification);
                    }
                    this.i.d.cancel(c1442p2.a);
                }
            } else {
                this.d = null;
            }
        }
        SystemForegroundService systemForegroundService2 = this.i;
        if (c1442p == null || systemForegroundService2 == null) {
            return;
        }
        z zVarC = z.c();
        jVar.toString();
        zVarC.getClass();
        systemForegroundService2.d.cancel(c1442p.a);
    }

    public final void c(Intent intent) {
        if (this.i == null) {
            throw new IllegalStateException("handleNotify was called on the destroyed dispatcher");
        }
        int i = 0;
        int intExtra = intent.getIntExtra("KEY_NOTIFICATION_ID", 0);
        int intExtra2 = intent.getIntExtra("KEY_FOREGROUND_SERVICE_TYPE", 0);
        androidx.work.impl.model.j jVar = new androidx.work.impl.model.j(intent.getStringExtra("KEY_WORKSPEC_ID"), intent.getIntExtra("KEY_GENERATION", 0));
        Notification notification = (Notification) intent.getParcelableExtra("KEY_NOTIFICATION");
        z.c().getClass();
        if (notification == null) {
            throw new IllegalArgumentException("Notification passed in the intent was null.");
        }
        C1442p c1442p = new C1442p(intExtra, notification, intExtra2);
        LinkedHashMap linkedHashMap = this.e;
        linkedHashMap.put(jVar, c1442p);
        C1442p c1442p2 = (C1442p) linkedHashMap.get(this.d);
        if (c1442p2 == null) {
            this.d = jVar;
        } else {
            this.i.d.notify(intExtra, notification);
            if (Build.VERSION.SDK_INT >= 29) {
                Iterator it2 = linkedHashMap.entrySet().iterator();
                while (it2.hasNext()) {
                    i |= ((C1442p) ((Map.Entry) it2.next()).getValue()).b;
                }
                c1442p = new C1442p(c1442p2.a, c1442p2.c, i);
            } else {
                c1442p = c1442p2;
            }
        }
        SystemForegroundService systemForegroundService = this.i;
        Notification notification2 = c1442p.c;
        systemForegroundService.getClass();
        int i2 = Build.VERSION.SDK_INT;
        int i3 = c1442p.a;
        int i4 = c1442p.b;
        if (i2 >= 31) {
            androidx.core.graphics.c.f(systemForegroundService, i3, notification2, i4);
        } else if (i2 >= 29) {
            androidx.core.graphics.c.e(systemForegroundService, i3, notification2, i4);
        } else {
            systemForegroundService.startForeground(i3, notification2);
        }
    }

    @Override // androidx.work.impl.constraints.j
    public final void d(q qVar, androidx.work.impl.constraints.c cVar) {
        if (cVar instanceof b) {
            z.c().getClass();
            androidx.work.impl.model.j jVarA = A2.a(qVar);
            int i = ((b) cVar).a;
            r rVar = this.a;
            rVar.getClass();
            rVar.d.a(new androidx.work.impl.utils.j(rVar.f, new androidx.work.impl.j(jVarA), true, i));
        }
    }

    public final void e() {
        this.i = null;
        synchronized (this.c) {
            try {
                Iterator it2 = this.g.values().iterator();
                while (it2.hasNext()) {
                    ((InterfaceC5025j0) it2.next()).j(null);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        this.a.f.f(this);
    }

    public final void f(int i) {
        z.c().d(j, android.support.v4.media.session.a.f(i, "Foreground service timed out, FGS type: "));
        for (Map.Entry entry : this.e.entrySet()) {
            if (((C1442p) entry.getValue()).b == i) {
                androidx.work.impl.model.j jVar = (androidx.work.impl.model.j) entry.getKey();
                r rVar = this.a;
                rVar.getClass();
                rVar.d.a(new androidx.work.impl.utils.j(rVar.f, new androidx.work.impl.j(jVar), true, -128));
            }
        }
        SystemForegroundService systemForegroundService = this.i;
        if (systemForegroundService != null) {
            systemForegroundService.b = true;
            z.c().getClass();
            systemForegroundService.stopForeground(true);
            systemForegroundService.stopSelf();
        }
    }
}
