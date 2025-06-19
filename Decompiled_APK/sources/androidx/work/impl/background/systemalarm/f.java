package androidx.work.impl.background.systemalarm;

import android.content.Context;
import android.content.Intent;
import android.os.PowerManager;
import androidx.appcompat.app.ExecutorC0060p;
import androidx.appcompat.widget.V;
import androidx.work.impl.constraints.j;
import androidx.work.impl.constraints.m;
import androidx.work.impl.constraints.o;
import androidx.work.impl.model.q;
import androidx.work.impl.utils.k;
import androidx.work.impl.utils.s;
import androidx.work.impl.utils.t;
import androidx.work.impl.utils.u;
import androidx.work.z;
import java.util.Objects;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.y0;

/* loaded from: classes.dex */
public final class f implements j, s {
    public final Context a;
    public final int b;
    public final androidx.work.impl.model.j c;
    public final h d;
    public final m e;
    public final Object f;
    public int g;
    public final ExecutorC0060p h;
    public final androidx.work.impl.utils.taskexecutor.b i;
    public PowerManager.WakeLock j;
    public boolean k;
    public final androidx.work.impl.j l;
    public final AbstractC5040y m;
    public volatile y0 n;

    static {
        z.e("DelayMetCommandHandler");
    }

    public f(Context context, int i, h hVar, androidx.work.impl.j jVar) {
        this.a = context;
        this.b = i;
        this.d = hVar;
        this.c = jVar.a;
        this.l = jVar;
        androidx.work.impl.constraints.trackers.j jVar2 = hVar.e.j;
        androidx.work.impl.utils.taskexecutor.c cVar = hVar.b;
        this.h = cVar.a;
        this.i = cVar.d;
        this.m = cVar.b;
        this.e = new m(jVar2);
        this.k = false;
        this.g = 0;
        this.f = new Object();
    }

    public static void a(f fVar) {
        androidx.work.impl.model.j jVar = fVar.c;
        String str = jVar.a;
        if (fVar.g >= 2) {
            z.c().getClass();
            return;
        }
        fVar.g = 2;
        z.c().getClass();
        Context context = fVar.a;
        Intent intent = new Intent(context, (Class<?>) SystemAlarmService.class);
        intent.setAction("ACTION_STOP_WORK");
        b.d(intent, jVar);
        h hVar = fVar.d;
        int i = fVar.b;
        V v = new V(hVar, intent, i, 4);
        androidx.work.impl.utils.taskexecutor.b bVar = fVar.i;
        bVar.execute(v);
        if (!hVar.d.e(jVar.a)) {
            z.c().getClass();
            return;
        }
        z.c().getClass();
        Intent intent2 = new Intent(context, (Class<?>) SystemAlarmService.class);
        intent2.setAction("ACTION_SCHEDULE_WORK");
        b.d(intent2, jVar);
        bVar.execute(new V(hVar, intent2, i, 4));
    }

    public static void b(f fVar) {
        if (fVar.g != 0) {
            z zVarC = z.c();
            Objects.toString(fVar.c);
            zVarC.getClass();
            return;
        }
        fVar.g = 1;
        z zVarC2 = z.c();
        Objects.toString(fVar.c);
        zVarC2.getClass();
        if (!fVar.d.d.h(fVar.l, null)) {
            fVar.c();
            return;
        }
        u uVar = fVar.d.c;
        androidx.work.impl.model.j jVar = fVar.c;
        synchronized (uVar.d) {
            z zVarC3 = z.c();
            Objects.toString(jVar);
            zVarC3.getClass();
            uVar.a(jVar);
            t tVar = new t(uVar, jVar);
            uVar.b.put(jVar, tVar);
            uVar.c.put(jVar, fVar);
            uVar.a.a.postDelayed(tVar, 600000L);
        }
    }

    public final void c() {
        synchronized (this.f) {
            try {
                if (this.n != null) {
                    this.n.j(null);
                }
                this.d.c.a(this.c);
                PowerManager.WakeLock wakeLock = this.j;
                if (wakeLock != null && wakeLock.isHeld()) {
                    z zVarC = z.c();
                    Objects.toString(this.j);
                    Objects.toString(this.c);
                    zVarC.getClass();
                    this.j.release();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.work.impl.constraints.j
    public final void d(q qVar, androidx.work.impl.constraints.c cVar) {
        boolean z = cVar instanceof androidx.work.impl.constraints.a;
        ExecutorC0060p executorC0060p = this.h;
        if (z) {
            executorC0060p.execute(new e(this, 1));
        } else {
            executorC0060p.execute(new e(this, 0));
        }
    }

    public final void e() {
        String str = this.c.a;
        Context context = this.a;
        StringBuilder sbX = android.support.v4.media.session.a.x(str, " (");
        sbX.append(this.b);
        sbX.append(")");
        this.j = k.a(context, sbX.toString());
        z zVarC = z.c();
        Objects.toString(this.j);
        zVarC.getClass();
        this.j.acquire();
        q qVarO = this.d.e.c.u().o(str);
        if (qVarO == null) {
            this.h.execute(new e(this, 0));
            return;
        }
        boolean zB = qVarO.b();
        this.k = zB;
        if (zB) {
            this.n = o.a(this.e, qVarO, this.m, this);
        } else {
            z.c().getClass();
            this.h.execute(new e(this, 1));
        }
    }

    public final void f(boolean z) {
        z zVarC = z.c();
        androidx.work.impl.model.j jVar = this.c;
        Objects.toString(jVar);
        zVarC.getClass();
        c();
        int i = this.b;
        h hVar = this.d;
        androidx.work.impl.utils.taskexecutor.b bVar = this.i;
        Context context = this.a;
        if (z) {
            Intent intent = new Intent(context, (Class<?>) SystemAlarmService.class);
            intent.setAction("ACTION_SCHEDULE_WORK");
            b.d(intent, jVar);
            bVar.execute(new V(hVar, intent, i, 4));
        }
        if (this.k) {
            Intent intent2 = new Intent(context, (Class<?>) SystemAlarmService.class);
            intent2.setAction("ACTION_CONSTRAINTS_CHANGED");
            bVar.execute(new V(hVar, intent2, i, 4));
        }
    }
}
