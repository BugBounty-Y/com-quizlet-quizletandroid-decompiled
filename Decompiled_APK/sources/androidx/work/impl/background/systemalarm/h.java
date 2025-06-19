package androidx.work.impl.background.systemalarm;

import android.content.Context;
import android.content.Intent;
import android.os.Looper;
import android.os.PowerManager;
import android.text.TextUtils;
import androidx.appcompat.widget.V;
import androidx.camera.core.impl.y0;
import androidx.work.impl.C1433e;
import androidx.work.impl.InterfaceC1430b;
import androidx.work.impl.model.j;
import androidx.work.impl.r;
import androidx.work.impl.utils.k;
import androidx.work.impl.utils.u;
import androidx.work.z;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;

/* loaded from: classes.dex */
public final class h implements InterfaceC1430b {
    public static final String k = z.e("SystemAlarmDispatcher");
    public final Context a;
    public final androidx.work.impl.utils.taskexecutor.c b;
    public final u c;
    public final C1433e d;
    public final r e;
    public final b f;
    public final ArrayList g;
    public Intent h;
    public SystemAlarmService i;
    public final androidx.work.impl.model.c j;

    public h(SystemAlarmService systemAlarmService) {
        Context applicationContext = systemAlarmService.getApplicationContext();
        this.a = applicationContext;
        androidx.compose.foundation.text.input.internal.u uVar = new androidx.compose.foundation.text.input.internal.u(new y0(2));
        r rVarH = r.h(systemAlarmService);
        this.e = rVarH;
        this.f = new b(applicationContext, rVarH.b.d, uVar);
        this.c = new u(rVarH.b.g);
        C1433e c1433e = rVarH.f;
        this.d = c1433e;
        androidx.work.impl.utils.taskexecutor.c cVar = rVarH.d;
        this.b = cVar;
        this.j = new androidx.work.impl.model.c(c1433e, cVar);
        c1433e.a(this);
        this.g = new ArrayList();
        this.h = null;
    }

    public static void c() {
        if (Looper.getMainLooper().getThread() != Thread.currentThread()) {
            throw new IllegalStateException("Needs to be invoked on the main thread.");
        }
    }

    public final void a(int i, Intent intent) {
        z zVarC = z.c();
        String str = k;
        Objects.toString(intent);
        zVarC.getClass();
        c();
        String action = intent.getAction();
        if (TextUtils.isEmpty(action)) {
            z.c().f(str, "Unknown command. Ignoring");
            return;
        }
        if ("ACTION_CONSTRAINTS_CHANGED".equals(action)) {
            c();
            synchronized (this.g) {
                try {
                    Iterator it2 = this.g.iterator();
                    while (it2.hasNext()) {
                        if ("ACTION_CONSTRAINTS_CHANGED".equals(((Intent) it2.next()).getAction())) {
                            return;
                        }
                    }
                } finally {
                }
            }
        }
        intent.putExtra("KEY_START_ID", i);
        synchronized (this.g) {
            try {
                boolean zIsEmpty = this.g.isEmpty();
                this.g.add(intent);
                if (zIsEmpty) {
                    d();
                }
            } finally {
            }
        }
    }

    @Override // androidx.work.impl.InterfaceC1430b
    public final void b(j jVar, boolean z) {
        androidx.work.impl.utils.taskexecutor.b bVar = this.b.d;
        String str = b.f;
        Intent intent = new Intent(this.a, (Class<?>) SystemAlarmService.class);
        intent.setAction("ACTION_EXECUTION_COMPLETED");
        intent.putExtra("KEY_NEEDS_RESCHEDULE", z);
        b.d(intent, jVar);
        bVar.execute(new V(this, intent, 0, 4));
    }

    public final void d() {
        c();
        PowerManager.WakeLock wakeLockA = k.a(this.a, "ProcessCommand");
        try {
            wakeLockA.acquire();
            this.e.d.a(new g(this, 0));
        } finally {
            wakeLockA.release();
        }
    }
}
