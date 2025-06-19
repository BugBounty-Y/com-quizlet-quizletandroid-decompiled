package androidx.work.impl.workers;

import android.content.Context;
import android.database.Cursor;
import androidx.room.u;
import androidx.work.A;
import androidx.work.C1425f;
import androidx.work.C1437k;
import androidx.work.EnumC1420a;
import androidx.work.J;
import androidx.work.N;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import androidx.work.impl.WorkDatabase;
import androidx.work.impl.WorkDatabase_Impl;
import androidx.work.impl.model.i;
import androidx.work.impl.model.l;
import androidx.work.impl.model.q;
import androidx.work.impl.model.t;
import androidx.work.impl.model.v;
import androidx.work.impl.r;
import androidx.work.impl.utils.g;
import androidx.work.w;
import androidx.work.x;
import androidx.work.z;
import com.google.android.gms.internal.mlkit_vision_camera.B2;
import com.google.android.gms.internal.mlkit_vision_camera.V1;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class DiagnosticsWorker extends Worker {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public DiagnosticsWorker(@NotNull Context context, @NotNull WorkerParameters parameters) {
        super(context, parameters);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(parameters, "parameters");
    }

    @Override // androidx.work.Worker
    public final x doWork() throws Throwable {
        u uVar;
        int iH;
        int iH2;
        int iH3;
        int iH4;
        int iH5;
        int iH6;
        int iH7;
        int iH8;
        int iH9;
        int iH10;
        int iH11;
        i iVar;
        l lVar;
        v vVar;
        r rVarH = r.h(getApplicationContext());
        Intrinsics.checkNotNullExpressionValue(rVarH, "getInstance(applicationContext)");
        WorkDatabase workDatabase = rVarH.c;
        Intrinsics.checkNotNullExpressionValue(workDatabase, "workManager.workDatabase");
        t tVarU = workDatabase.u();
        l lVarS = workDatabase.s();
        v vVarV = workDatabase.v();
        i iVarQ = workDatabase.q();
        rVarH.b.d.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1L);
        tVarU.getClass();
        u uVarA = u.a(1, "SELECT * FROM workspec WHERE last_enqueue_time >= ? AND state IN (2, 3, 5) ORDER BY last_enqueue_time DESC");
        uVarA.z(1, jCurrentTimeMillis);
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) tVarU.a;
        workDatabase_Impl.b();
        Cursor cursorN = W1.N(workDatabase_Impl, uVarA, false);
        try {
            iH = V1.H(cursorN, "id");
            iH2 = V1.H(cursorN, "state");
            iH3 = V1.H(cursorN, "worker_class_name");
            iH4 = V1.H(cursorN, "input_merger_class_name");
            iH5 = V1.H(cursorN, "input");
            iH6 = V1.H(cursorN, "output");
            iH7 = V1.H(cursorN, "initial_delay");
            iH8 = V1.H(cursorN, "interval_duration");
            iH9 = V1.H(cursorN, "flex_duration");
            iH10 = V1.H(cursorN, "run_attempt_count");
            iH11 = V1.H(cursorN, "backoff_policy");
            uVar = uVarA;
        } catch (Throwable th) {
            th = th;
            uVar = uVarA;
        }
        try {
            int iH12 = V1.H(cursorN, "backoff_delay_duration");
            int iH13 = V1.H(cursorN, "last_enqueue_time");
            int iH14 = V1.H(cursorN, "minimum_retention_duration");
            int iH15 = V1.H(cursorN, "schedule_requested_at");
            int iH16 = V1.H(cursorN, "run_in_foreground");
            int iH17 = V1.H(cursorN, "out_of_quota_policy");
            int iH18 = V1.H(cursorN, "period_count");
            int iH19 = V1.H(cursorN, "generation");
            int iH20 = V1.H(cursorN, "next_schedule_time_override");
            int iH21 = V1.H(cursorN, "next_schedule_time_override_generation");
            int iH22 = V1.H(cursorN, "stop_reason");
            int iH23 = V1.H(cursorN, "trace_tag");
            int iH24 = V1.H(cursorN, "required_network_type");
            int iH25 = V1.H(cursorN, "required_network_request");
            int iH26 = V1.H(cursorN, "requires_charging");
            int iH27 = V1.H(cursorN, "requires_device_idle");
            int iH28 = V1.H(cursorN, "requires_battery_not_low");
            int iH29 = V1.H(cursorN, "requires_storage_not_low");
            int iH30 = V1.H(cursorN, "trigger_content_update_delay");
            int iH31 = V1.H(cursorN, "trigger_max_content_delay");
            int iH32 = V1.H(cursorN, "content_uri_triggers");
            int i = iH14;
            ArrayList arrayList = new ArrayList(cursorN.getCount());
            while (cursorN.moveToNext()) {
                String string = cursorN.getString(iH);
                N nF = B2.f(cursorN.getInt(iH2));
                String string2 = cursorN.getString(iH3);
                String string3 = cursorN.getString(iH4);
                C1437k c1437kA = C1437k.a(cursorN.getBlob(iH5));
                C1437k c1437kA2 = C1437k.a(cursorN.getBlob(iH6));
                long j = cursorN.getLong(iH7);
                long j2 = cursorN.getLong(iH8);
                long j3 = cursorN.getLong(iH9);
                int i2 = cursorN.getInt(iH10);
                EnumC1420a enumC1420aC = B2.c(cursorN.getInt(iH11));
                long j4 = cursorN.getLong(iH12);
                long j5 = cursorN.getLong(iH13);
                int i3 = i;
                long j6 = cursorN.getLong(i3);
                int i4 = iH;
                int i5 = iH15;
                long j7 = cursorN.getLong(i5);
                iH15 = i5;
                int i6 = iH16;
                boolean z = cursorN.getInt(i6) != 0;
                iH16 = i6;
                int i7 = iH17;
                J jE = B2.e(cursorN.getInt(i7));
                iH17 = i7;
                int i8 = iH18;
                int i9 = cursorN.getInt(i8);
                iH18 = i8;
                int i10 = iH19;
                int i11 = cursorN.getInt(i10);
                iH19 = i10;
                int i12 = iH20;
                long j8 = cursorN.getLong(i12);
                iH20 = i12;
                int i13 = iH21;
                int i14 = cursorN.getInt(i13);
                iH21 = i13;
                int i15 = iH22;
                int i16 = cursorN.getInt(i15);
                iH22 = i15;
                int i17 = iH23;
                String string4 = cursorN.isNull(i17) ? null : cursorN.getString(i17);
                iH23 = i17;
                int i18 = iH24;
                A aD = B2.d(cursorN.getInt(i18));
                iH24 = i18;
                int i19 = iH25;
                g gVarH = B2.h(cursorN.getBlob(i19));
                iH25 = i19;
                int i20 = iH26;
                boolean z2 = cursorN.getInt(i20) != 0;
                iH26 = i20;
                int i21 = iH27;
                boolean z3 = cursorN.getInt(i21) != 0;
                iH27 = i21;
                int i22 = iH28;
                boolean z4 = cursorN.getInt(i22) != 0;
                iH28 = i22;
                int i23 = iH29;
                boolean z5 = cursorN.getInt(i23) != 0;
                iH29 = i23;
                int i24 = iH30;
                long j9 = cursorN.getLong(i24);
                iH30 = i24;
                int i25 = iH31;
                long j10 = cursorN.getLong(i25);
                iH31 = i25;
                int i26 = iH32;
                iH32 = i26;
                arrayList.add(new q(string, nF, string2, string3, c1437kA, c1437kA2, j, j2, j3, new C1425f(gVarH, aD, z2, z3, z4, z5, j9, j10, B2.a(cursorN.getBlob(i26))), i2, enumC1420aC, j4, j5, j6, j7, z, jE, i9, i11, j8, i14, i16, string4));
                iH = i4;
                i = i3;
            }
            cursorN.close();
            uVar.i();
            ArrayList arrayListL = tVarU.l();
            ArrayList arrayListG = tVarU.g();
            if (arrayList.isEmpty()) {
                iVar = iVarQ;
                lVar = lVarS;
                vVar = vVarV;
            } else {
                z zVarC = z.c();
                String str = a.a;
                zVarC.d(str, "Recently completed work:\n\n");
                iVar = iVarQ;
                lVar = lVarS;
                vVar = vVarV;
                z.c().d(str, a.a(lVar, vVar, iVar, arrayList));
            }
            if (!arrayListL.isEmpty()) {
                z zVarC2 = z.c();
                String str2 = a.a;
                zVarC2.d(str2, "Running work:\n\n");
                z.c().d(str2, a.a(lVar, vVar, iVar, arrayListL));
            }
            if (!arrayListG.isEmpty()) {
                z zVarC3 = z.c();
                String str3 = a.a;
                zVarC3.d(str3, "Enqueued work:\n\n");
                z.c().d(str3, a.a(lVar, vVar, iVar, arrayListG));
            }
            w wVarA = x.a();
            Intrinsics.checkNotNullExpressionValue(wVarA, "success()");
            return wVarA;
        } catch (Throwable th2) {
            th = th2;
            cursorN.close();
            uVar.i();
            throw th;
        }
    }
}
