package androidx.work.impl.background.systemalarm;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.widget.V;
import androidx.compose.foundation.text.input.internal.u;
import androidx.work.A;
import androidx.work.B;
import androidx.work.C1425f;
import androidx.work.impl.InterfaceC1430b;
import androidx.work.impl.WorkDatabase;
import androidx.work.impl.WorkDatabase_Impl;
import androidx.work.impl.constraints.l;
import androidx.work.impl.constraints.m;
import androidx.work.impl.constraints.o;
import androidx.work.impl.model.i;
import androidx.work.impl.model.j;
import androidx.work.impl.model.q;
import androidx.work.z;
import com.google.android.gms.internal.mlkit_vision_camera.A2;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements InterfaceC1430b {
    public static final String f = z.e("CommandHandler");
    public final Context a;
    public final HashMap b = new HashMap();
    public final Object c = new Object();
    public final B d;
    public final u e;

    public b(Context context, B b, u uVar) {
        this.a = context;
        this.d = b;
        this.e = uVar;
    }

    public static j c(Intent intent) {
        return new j(intent.getStringExtra("KEY_WORKSPEC_ID"), intent.getIntExtra("KEY_WORKSPEC_GENERATION", 0));
    }

    public static void d(Intent intent, j jVar) {
        intent.putExtra("KEY_WORKSPEC_ID", jVar.a);
        intent.putExtra("KEY_WORKSPEC_GENERATION", jVar.b);
    }

    public final void a(Intent intent, int i, h hVar) {
        List<androidx.work.impl.j> listR;
        int i2 = 4;
        String action = intent.getAction();
        if ("ACTION_CONSTRAINTS_CHANGED".equals(action)) {
            z zVarC = z.c();
            Objects.toString(intent);
            zVarC.getClass();
            d dVar = new d(this.a, this.d, i, hVar);
            ArrayList arrayListM = hVar.e.c.u().m();
            int i3 = c.a;
            Iterator it2 = arrayListM.iterator();
            boolean z = false;
            boolean z2 = false;
            boolean z3 = false;
            boolean z4 = false;
            while (it2.hasNext()) {
                C1425f c1425f = ((q) it2.next()).j;
                z |= c1425f.e;
                z2 |= c1425f.c;
                z3 |= c1425f.f;
                z4 |= c1425f.a != A.a;
                if (z && z2 && z3 && z4) {
                    break;
                }
            }
            int i4 = ConstraintProxyUpdateReceiver.a;
            Intent intent2 = new Intent("androidx.work.impl.background.systemalarm.UpdateProxies");
            Context context = dVar.a;
            intent2.setComponent(new ComponentName(context, (Class<?>) ConstraintProxyUpdateReceiver.class));
            intent2.putExtra("KEY_BATTERY_NOT_LOW_PROXY_ENABLED", z).putExtra("KEY_BATTERY_CHARGING_PROXY_ENABLED", z2).putExtra("KEY_STORAGE_NOT_LOW_PROXY_ENABLED", z3).putExtra("KEY_NETWORK_STATE_PROXY_ENABLED", z4);
            context.sendBroadcast(intent2);
            ArrayList arrayList = new ArrayList(arrayListM.size());
            dVar.b.getClass();
            long jCurrentTimeMillis = System.currentTimeMillis();
            Iterator it3 = arrayListM.iterator();
            while (it3.hasNext()) {
                q workSpec = (q) it3.next();
                if (jCurrentTimeMillis >= workSpec.a()) {
                    if (workSpec.b()) {
                        m mVar = dVar.d;
                        mVar.getClass();
                        Intrinsics.checkNotNullParameter(workSpec, "workSpec");
                        ArrayList arrayList2 = new ArrayList();
                        Iterator it4 = mVar.a.iterator();
                        while (it4.hasNext()) {
                            Object next = it4.next();
                            if (((androidx.work.impl.constraints.controllers.e) next).c(workSpec)) {
                                arrayList2.add(next);
                            }
                        }
                        if (!arrayList2.isEmpty()) {
                            z zVarC2 = z.c();
                            int i5 = o.a;
                            CollectionsKt.S(arrayList2, null, null, null, l.a, 31);
                            zVarC2.getClass();
                        }
                        if (arrayList2.isEmpty()) {
                        }
                    }
                    arrayList.add(workSpec);
                }
            }
            Iterator it5 = arrayList.iterator();
            while (it5.hasNext()) {
                q qVar = (q) it5.next();
                String str = qVar.a;
                j jVarA = A2.a(qVar);
                Intent intent3 = new Intent(context, (Class<?>) SystemAlarmService.class);
                intent3.setAction("ACTION_DELAY_MET");
                d(intent3, jVarA);
                z.c().getClass();
                hVar.b.d.execute(new V(hVar, intent3, dVar.c, i2));
            }
            return;
        }
        if ("ACTION_RESCHEDULE".equals(action)) {
            z zVarC3 = z.c();
            Objects.toString(intent);
            zVarC3.getClass();
            hVar.e.k();
            return;
        }
        Bundle extras = intent.getExtras();
        String[] strArr = {"KEY_WORKSPEC_ID"};
        if (extras == null || extras.isEmpty() || extras.get(strArr[0]) == null) {
            z.c().a(f, "Invalid request for " + action + " , requires KEY_WORKSPEC_ID .");
            return;
        }
        if ("ACTION_SCHEDULE_WORK".equals(action)) {
            j jVarC = c(intent);
            z zVarC4 = z.c();
            jVarC.toString();
            zVarC4.getClass();
            WorkDatabase workDatabase = hVar.e.c;
            workDatabase.c();
            try {
                q qVarO = workDatabase.u().o(jVarC.a);
                String str2 = f;
                if (qVarO == null) {
                    z.c().f(str2, "Skipping scheduling " + jVarC + " because it's no longer in the DB");
                    return;
                }
                if (qVarO.b.a()) {
                    z.c().f(str2, "Skipping scheduling " + jVarC + "because it is finished.");
                    return;
                }
                long jA = qVarO.a();
                boolean zB = qVarO.b();
                Context context2 = this.a;
                if (zB) {
                    z zVarC5 = z.c();
                    jVarC.toString();
                    zVarC5.getClass();
                    a.b(context2, workDatabase, jVarC, jA);
                    Intent intent4 = new Intent(context2, (Class<?>) SystemAlarmService.class);
                    intent4.setAction("ACTION_CONSTRAINTS_CHANGED");
                    hVar.b.d.execute(new V(hVar, intent4, i, i2));
                } else {
                    z zVarC6 = z.c();
                    jVarC.toString();
                    zVarC6.getClass();
                    a.b(context2, workDatabase, jVarC, jA);
                }
                workDatabase.p();
                return;
            } finally {
                workDatabase.k();
            }
        }
        if ("ACTION_DELAY_MET".equals(action)) {
            synchronized (this.c) {
                try {
                    j jVarC2 = c(intent);
                    z zVarC7 = z.c();
                    jVarC2.toString();
                    zVarC7.getClass();
                    if (this.b.containsKey(jVarC2)) {
                        z zVarC8 = z.c();
                        jVarC2.toString();
                        zVarC8.getClass();
                    } else {
                        f fVar = new f(this.a, i, hVar, this.e.t(jVarC2));
                        this.b.put(jVarC2, fVar);
                        fVar.e();
                    }
                } finally {
                }
            }
            return;
        }
        if (!"ACTION_STOP_WORK".equals(action)) {
            if (!"ACTION_EXECUTION_COMPLETED".equals(action)) {
                z.c().f(f, "Ignoring intent " + intent);
                return;
            }
            j jVarC3 = c(intent);
            boolean z5 = intent.getExtras().getBoolean("KEY_NEEDS_RESCHEDULE");
            z zVarC9 = z.c();
            intent.toString();
            zVarC9.getClass();
            b(jVarC3, z5);
            return;
        }
        Bundle extras2 = intent.getExtras();
        String string = extras2.getString("KEY_WORKSPEC_ID");
        boolean zContainsKey = extras2.containsKey("KEY_WORKSPEC_GENERATION");
        u uVar = this.e;
        if (zContainsKey) {
            int i6 = extras2.getInt("KEY_WORKSPEC_GENERATION");
            ArrayList arrayList3 = new ArrayList(1);
            androidx.work.impl.j jVarQ = uVar.q(new j(string, i6));
            listR = arrayList3;
            if (jVarQ != null) {
                arrayList3.add(jVarQ);
                listR = arrayList3;
            }
        } else {
            listR = uVar.r(string);
        }
        for (androidx.work.impl.j workSpecId : listR) {
            z.c().getClass();
            androidx.work.impl.model.c cVar = hVar.j;
            cVar.getClass();
            Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
            cVar.z(workSpecId, -512);
            WorkDatabase workDatabase2 = hVar.e.c;
            int i7 = a.a;
            i iVarQ = workDatabase2.q();
            j id = workSpecId.a;
            androidx.work.impl.model.g gVarD = iVarQ.d(id);
            if (gVarD != null) {
                a.a(this.a, id, gVarD.c);
                z zVarC10 = z.c();
                id.toString();
                zVarC10.getClass();
                Intrinsics.checkNotNullParameter(id, "id");
                WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) iVarQ.b;
                workDatabase_Impl.b();
                androidx.work.impl.model.h hVar2 = (androidx.work.impl.model.h) iVarQ.d;
                androidx.sqlite.db.framework.i iVarA = hVar2.a();
                iVarA.g(1, id.a);
                iVarA.z(2, id.b);
                try {
                    workDatabase_Impl.c();
                    try {
                        iVarA.a();
                        workDatabase_Impl.p();
                        workDatabase_Impl.k();
                    } catch (Throwable th) {
                        workDatabase_Impl.k();
                        throw th;
                    }
                } finally {
                    hVar2.n(iVarA);
                }
            }
            hVar.b(id, false);
        }
    }

    @Override // androidx.work.impl.InterfaceC1430b
    public final void b(j jVar, boolean z) {
        synchronized (this.c) {
            try {
                f fVar = (f) this.b.remove(jVar);
                this.e.q(jVar);
                if (fVar != null) {
                    fVar.f(z);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
