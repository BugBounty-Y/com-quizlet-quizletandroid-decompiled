package androidx.work.impl.model;

import android.database.Cursor;
import androidx.compose.animation.core.D;
import androidx.compose.animation.d0;
import androidx.compose.material3.internal.AbstractC0646j;
import androidx.compose.material3.internal.C0648l;
import androidx.compose.material3.internal.E;
import androidx.compose.material3.internal.F;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.F0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.V;
import androidx.work.A;
import androidx.work.C1425f;
import androidx.work.C1437k;
import androidx.work.EnumC1420a;
import androidx.work.J;
import androidx.work.N;
import androidx.work.impl.WorkDatabase_Impl;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3390s2;
import com.google.android.gms.internal.mlkit_vision_camera.B2;
import com.google.android.gms.internal.mlkit_vision_camera.V1;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import com.google.android.gms.internal.mlkit_vision_camera.X1;
import com.google.android.gms.internal.mlkit_vision_camera.Y1;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class t {
    public final Object a;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final Object f;
    public final Object g;
    public final Object h;
    public final Object i;
    public final Object j;
    public final Object k;
    public final Object l;
    public final Object m;
    public final Object n;

    public t(WorkDatabase_Impl database) {
        this.a = database;
        Intrinsics.checkNotNullParameter(database, "database");
        this.b = new b(database, 5);
        Intrinsics.checkNotNullParameter(database, "database");
        new h(database, 12);
        this.c = new h(database, 13);
        this.d = new h(database, 14);
        this.e = new h(database, 15);
        this.f = new h(database, 16);
        this.g = new h(database, 17);
        this.h = new h(database, 18);
        this.i = new h(database, 19);
        this.j = new h(database, 4);
        new h(database, 5);
        this.k = new h(database, 6);
        this.l = new h(database, 7);
        this.m = new h(database, 8);
        new h(database, 9);
        new h(database, 10);
        this.n = new h(database, 11);
    }

    public Object A(float f, kotlin.coroutines.jvm.internal.i iVar) {
        Object value = ((L0) ((InterfaceC0773a0) this.g)).getValue();
        Object objE = e(s(), f, value);
        if (((Boolean) ((Function1) this.d).invoke(objE)).booleanValue()) {
            Object objC = AbstractC0646j.c(this, objE, f, iVar);
            return objC == kotlin.coroutines.intrinsics.a.a ? objC : Unit.a;
        }
        Object objC2 = AbstractC0646j.c(this, value, f, iVar);
        return objC2 == kotlin.coroutines.intrinsics.a.a ? objC2 : Unit.a;
    }

    public void a(HashMap map) {
        Set setKeySet = map.keySet();
        if (setKeySet.isEmpty()) {
            return;
        }
        if (map.size() > 999) {
            X1.e(map, new r(this, 1));
            return;
        }
        StringBuilder sbU = d0.u("SELECT `progress`,`work_spec_id` FROM `WorkProgress` WHERE `work_spec_id` IN (");
        int size = setKeySet.size();
        Y1.d(sbU, size);
        sbU.append(")");
        androidx.room.u uVarA = androidx.room.u.a(size, sbU.toString());
        Iterator it2 = setKeySet.iterator();
        int i = 1;
        while (it2.hasNext()) {
            uVarA.g(i, (String) it2.next());
            i++;
        }
        Cursor cursorN = W1.N((WorkDatabase_Impl) this.a, uVarA, false);
        try {
            int iG = V1.G(cursorN, "work_spec_id");
            if (iG == -1) {
                return;
            }
            while (cursorN.moveToNext()) {
                ArrayList arrayList = (ArrayList) map.get(cursorN.getString(iG));
                if (arrayList != null) {
                    arrayList.add(C1437k.a(cursorN.getBlob(0)));
                }
            }
        } finally {
            cursorN.close();
        }
    }

    public void b(HashMap map) {
        Set setKeySet = map.keySet();
        if (setKeySet.isEmpty()) {
            return;
        }
        if (map.size() > 999) {
            X1.e(map, new r(this, 0));
            return;
        }
        StringBuilder sbU = d0.u("SELECT `tag`,`work_spec_id` FROM `WorkTag` WHERE `work_spec_id` IN (");
        int size = setKeySet.size();
        Y1.d(sbU, size);
        sbU.append(")");
        androidx.room.u uVarA = androidx.room.u.a(size, sbU.toString());
        Iterator it2 = setKeySet.iterator();
        int i = 1;
        while (it2.hasNext()) {
            uVarA.g(i, (String) it2.next());
            i++;
        }
        Cursor cursorN = W1.N((WorkDatabase_Impl) this.a, uVarA, false);
        try {
            int iG = V1.G(cursorN, "work_spec_id");
            if (iG == -1) {
                return;
            }
            while (cursorN.moveToNext()) {
                ArrayList arrayList = (ArrayList) map.get(cursorN.getString(iG));
                if (arrayList != null) {
                    arrayList.add(cursorN.getString(0));
                }
            }
        } finally {
            cursorN.close();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(androidx.compose.foundation.u0 r7, androidx.compose.material.C0574q r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r9 instanceof androidx.compose.material3.internal.C0647k
            if (r0 == 0) goto L13
            r0 = r9
            androidx.compose.material3.internal.k r0 = (androidx.compose.material3.internal.C0647k) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.compose.material3.internal.k r0 = new androidx.compose.material3.internal.k
            r0.<init>(r6, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1056964608(0x3f000000, float:0.5)
            r4 = 1
            if (r2 == 0) goto L36
            if (r2 != r4) goto L2e
            androidx.work.impl.model.t r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L2b
            goto L57
        L2b:
            r8 = move-exception
            goto L9a
        L2e:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r6.e     // Catch: java.lang.Throwable -> L98
            androidx.compose.material3.internal.E r9 = (androidx.compose.material3.internal.E) r9     // Catch: java.lang.Throwable -> L98
            androidx.compose.material3.internal.n r2 = new androidx.compose.material3.internal.n     // Catch: java.lang.Throwable -> L96
            r5 = 0
            r2.<init>(r8, r6, r5)     // Catch: java.lang.Throwable -> L96
            r0.j = r6     // Catch: java.lang.Throwable -> L96
            r0.m = r4     // Catch: java.lang.Throwable -> L96
            r9.getClass()     // Catch: java.lang.Throwable -> L92
            androidx.compose.material3.internal.D r8 = new androidx.compose.material3.internal.D     // Catch: java.lang.Throwable -> L92
            r8.<init>(r7, r9, r2, r5)     // Catch: java.lang.Throwable -> L92
            java.lang.Object r7 = kotlinx.coroutines.E.m(r8, r0)     // Catch: java.lang.Throwable -> L92
            if (r7 != r1) goto L56
            return r1
        L56:
            r7 = r6
        L57:
            androidx.compose.material3.internal.F r8 = r7.h()
            float r9 = r7.k()
            java.lang.Object r8 = r8.a(r9)
            if (r8 == 0) goto L8d
            float r9 = r7.k()
            androidx.compose.material3.internal.F r0 = r7.h()
            float r0 = r0.c(r8)
            float r9 = r9 - r0
            float r9 = java.lang.Math.abs(r9)
            int r9 = (r9 > r3 ? 1 : (r9 == r3 ? 0 : -1))
            if (r9 > 0) goto L8d
            java.lang.Object r9 = r7.d
            kotlin.jvm.functions.Function1 r9 = (kotlin.jvm.functions.Function1) r9
            java.lang.Object r9 = r9.invoke(r8)
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            if (r9 == 0) goto L8d
            r7.u(r8)
        L8d:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        L90:
            r8 = r7
            goto L94
        L92:
            r7 = move-exception
            goto L90
        L94:
            r7 = r6
            goto L9a
        L96:
            r8 = move-exception
            goto L94
        L98:
            r7 = move-exception
            goto L90
        L9a:
            androidx.compose.material3.internal.F r9 = r7.h()
            float r0 = r7.k()
            java.lang.Object r9 = r9.a(r0)
            if (r9 == 0) goto Ld0
            float r0 = r7.k()
            androidx.compose.material3.internal.F r1 = r7.h()
            float r1 = r1.c(r9)
            float r0 = r0 - r1
            float r0 = java.lang.Math.abs(r0)
            int r0 = (r0 > r3 ? 1 : (r0 == r3 ? 0 : -1))
            if (r0 > 0) goto Ld0
            java.lang.Object r0 = r7.d
            kotlin.jvm.functions.Function1 r0 = (kotlin.jvm.functions.Function1) r0
            java.lang.Object r0 = r0.invoke(r9)
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            if (r0 == 0) goto Ld0
            r7.u(r9)
        Ld0:
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.t.c(androidx.compose.foundation.u0, androidx.compose.material.q, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x00b8  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r10v3, types: [java.lang.Object, java.util.Map] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object d(java.lang.Object r7, androidx.compose.foundation.u0 r8, androidx.compose.material.C0560c r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            Method dump skipped, instructions count: 231
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.t.d(java.lang.Object, androidx.compose.foundation.u0, androidx.compose.material.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    public Object e(float f, float f2, Object obj) {
        F fH = h();
        float fC = fH.c(obj);
        float fFloatValue = ((Number) ((kotlin.jvm.internal.r) this.b).invoke()).floatValue();
        if (fC != f && !Float.isNaN(fC)) {
            Function1 function1 = (Function1) this.a;
            if (fC < f) {
                if (f2 >= fFloatValue) {
                    Object objB = fH.b(f, true);
                    Intrinsics.d(objB);
                    return objB;
                }
                Object objB2 = fH.b(f, true);
                Intrinsics.d(objB2);
                if (f >= Math.abs(Math.abs(((Number) function1.invoke(Float.valueOf(Math.abs(fH.c(objB2) - fC)))).floatValue()) + fC)) {
                    return objB2;
                }
            } else {
                if (f2 <= (-fFloatValue)) {
                    Object objB3 = fH.b(f, false);
                    Intrinsics.d(objB3);
                    return objB3;
                }
                Object objB4 = fH.b(f, false);
                Intrinsics.d(objB4);
                float fAbs = Math.abs(fC - Math.abs(((Number) function1.invoke(Float.valueOf(Math.abs(fC - fH.c(objB4))))).floatValue()));
                if (f >= DefinitionKt.NO_Float_VALUE ? f <= fAbs : Math.abs(f) >= fAbs) {
                    return objB4;
                }
            }
        }
        return obj;
    }

    public void f(String str) {
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
        workDatabase_Impl.b();
        h hVar = (h) this.c;
        androidx.sqlite.db.framework.i iVarA = hVar.a();
        iVarA.g(1, str);
        try {
            workDatabase_Impl.c();
            try {
                iVarA.a();
                workDatabase_Impl.p();
            } finally {
                workDatabase_Impl.k();
            }
        } finally {
            hVar.n(iVarA);
        }
    }

    public ArrayList g() throws Throwable {
        androidx.room.u uVar;
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
        int iH12;
        int iH13;
        androidx.room.u uVarA = androidx.room.u.a(1, "SELECT * FROM workspec WHERE state=0 ORDER BY last_enqueue_time LIMIT ?");
        uVarA.z(1, 200);
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
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
            iH12 = V1.H(cursorN, "backoff_delay_duration");
            iH13 = V1.H(cursorN, "last_enqueue_time");
            uVar = uVarA;
        } catch (Throwable th) {
            th = th;
            uVar = uVarA;
        }
        try {
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
                androidx.work.impl.utils.g gVarH = B2.h(cursorN.getBlob(i19));
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
            return arrayList;
        } catch (Throwable th2) {
            th = th2;
            cursorN.close();
            uVar.i();
            throw th;
        }
    }

    public F h() {
        return (F) ((L0) ((InterfaceC0773a0) this.m)).getValue();
    }

    public ArrayList i(int i) throws Throwable {
        androidx.room.u uVar;
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
        int iH12;
        int iH13;
        androidx.room.u uVarA = androidx.room.u.a(1, "SELECT * FROM workspec WHERE state=0 AND schedule_requested_at=-1 ORDER BY last_enqueue_time LIMIT (SELECT MAX(?-COUNT(*), 0) FROM workspec WHERE schedule_requested_at<>-1 AND LENGTH(content_uri_triggers)=0 AND state NOT IN (2, 3, 5))");
        uVarA.z(1, i);
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
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
            iH12 = V1.H(cursorN, "backoff_delay_duration");
            iH13 = V1.H(cursorN, "last_enqueue_time");
            uVar = uVarA;
        } catch (Throwable th) {
            th = th;
            uVar = uVarA;
        }
        try {
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
            int i2 = iH14;
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
                int i3 = cursorN.getInt(iH10);
                EnumC1420a enumC1420aC = B2.c(cursorN.getInt(iH11));
                long j4 = cursorN.getLong(iH12);
                long j5 = cursorN.getLong(iH13);
                int i4 = i2;
                long j6 = cursorN.getLong(i4);
                int i5 = iH;
                int i6 = iH15;
                long j7 = cursorN.getLong(i6);
                iH15 = i6;
                int i7 = iH16;
                boolean z = cursorN.getInt(i7) != 0;
                iH16 = i7;
                int i8 = iH17;
                J jE = B2.e(cursorN.getInt(i8));
                iH17 = i8;
                int i9 = iH18;
                int i10 = cursorN.getInt(i9);
                iH18 = i9;
                int i11 = iH19;
                int i12 = cursorN.getInt(i11);
                iH19 = i11;
                int i13 = iH20;
                long j8 = cursorN.getLong(i13);
                iH20 = i13;
                int i14 = iH21;
                int i15 = cursorN.getInt(i14);
                iH21 = i14;
                int i16 = iH22;
                int i17 = cursorN.getInt(i16);
                iH22 = i16;
                int i18 = iH23;
                String string4 = cursorN.isNull(i18) ? null : cursorN.getString(i18);
                iH23 = i18;
                int i19 = iH24;
                A aD = B2.d(cursorN.getInt(i19));
                iH24 = i19;
                int i20 = iH25;
                androidx.work.impl.utils.g gVarH = B2.h(cursorN.getBlob(i20));
                iH25 = i20;
                int i21 = iH26;
                boolean z2 = cursorN.getInt(i21) != 0;
                iH26 = i21;
                int i22 = iH27;
                boolean z3 = cursorN.getInt(i22) != 0;
                iH27 = i22;
                int i23 = iH28;
                boolean z4 = cursorN.getInt(i23) != 0;
                iH28 = i23;
                int i24 = iH29;
                boolean z5 = cursorN.getInt(i24) != 0;
                iH29 = i24;
                int i25 = iH30;
                long j9 = cursorN.getLong(i25);
                iH30 = i25;
                int i26 = iH31;
                long j10 = cursorN.getLong(i26);
                iH31 = i26;
                int i27 = iH32;
                iH32 = i27;
                arrayList.add(new q(string, nF, string2, string3, c1437kA, c1437kA2, j, j2, j3, new C1425f(gVarH, aD, z2, z3, z4, z5, j9, j10, B2.a(cursorN.getBlob(i27))), i3, enumC1420aC, j4, j5, j6, j7, z, jE, i10, i12, j8, i15, i17, string4));
                iH = i5;
                i2 = i4;
            }
            cursorN.close();
            uVar.i();
            return arrayList;
        } catch (Throwable th2) {
            th = th2;
            cursorN.close();
            uVar.i();
            throw th;
        }
    }

    public ArrayList j() throws Throwable {
        androidx.room.u uVar;
        androidx.room.u uVarA = androidx.room.u.a(0, "SELECT * FROM workspec WHERE state=0 AND schedule_requested_at=-1 AND LENGTH(content_uri_triggers)<>0 ORDER BY last_enqueue_time");
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
        workDatabase_Impl.b();
        Cursor cursorN = W1.N(workDatabase_Impl, uVarA, false);
        try {
            int iH = V1.H(cursorN, "id");
            int iH2 = V1.H(cursorN, "state");
            int iH3 = V1.H(cursorN, "worker_class_name");
            int iH4 = V1.H(cursorN, "input_merger_class_name");
            int iH5 = V1.H(cursorN, "input");
            int iH6 = V1.H(cursorN, "output");
            int iH7 = V1.H(cursorN, "initial_delay");
            int iH8 = V1.H(cursorN, "interval_duration");
            int iH9 = V1.H(cursorN, "flex_duration");
            int iH10 = V1.H(cursorN, "run_attempt_count");
            int iH11 = V1.H(cursorN, "backoff_policy");
            int iH12 = V1.H(cursorN, "backoff_delay_duration");
            int iH13 = V1.H(cursorN, "last_enqueue_time");
            uVar = uVarA;
            try {
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
                    androidx.work.impl.utils.g gVarH = B2.h(cursorN.getBlob(i19));
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
                return arrayList;
            } catch (Throwable th) {
                th = th;
                cursorN.close();
                uVar.i();
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            uVar = uVarA;
        }
    }

    public float k() {
        return ((F0) this.j).i();
    }

    public ArrayList l() throws Throwable {
        androidx.room.u uVar;
        androidx.room.u uVarA = androidx.room.u.a(0, "SELECT * FROM workspec WHERE state=1");
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
        workDatabase_Impl.b();
        Cursor cursorN = W1.N(workDatabase_Impl, uVarA, false);
        try {
            int iH = V1.H(cursorN, "id");
            int iH2 = V1.H(cursorN, "state");
            int iH3 = V1.H(cursorN, "worker_class_name");
            int iH4 = V1.H(cursorN, "input_merger_class_name");
            int iH5 = V1.H(cursorN, "input");
            int iH6 = V1.H(cursorN, "output");
            int iH7 = V1.H(cursorN, "initial_delay");
            int iH8 = V1.H(cursorN, "interval_duration");
            int iH9 = V1.H(cursorN, "flex_duration");
            int iH10 = V1.H(cursorN, "run_attempt_count");
            int iH11 = V1.H(cursorN, "backoff_policy");
            int iH12 = V1.H(cursorN, "backoff_delay_duration");
            int iH13 = V1.H(cursorN, "last_enqueue_time");
            uVar = uVarA;
            try {
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
                    androidx.work.impl.utils.g gVarH = B2.h(cursorN.getBlob(i19));
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
                return arrayList;
            } catch (Throwable th) {
                th = th;
                cursorN.close();
                uVar.i();
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            uVar = uVarA;
        }
    }

    public ArrayList m() {
        androidx.room.u uVar;
        androidx.room.u uVarA = androidx.room.u.a(0, "SELECT * FROM workspec WHERE state=0 AND schedule_requested_at<>-1");
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
        workDatabase_Impl.b();
        Cursor cursorN = W1.N(workDatabase_Impl, uVarA, false);
        try {
            int iH = V1.H(cursorN, "id");
            int iH2 = V1.H(cursorN, "state");
            int iH3 = V1.H(cursorN, "worker_class_name");
            int iH4 = V1.H(cursorN, "input_merger_class_name");
            int iH5 = V1.H(cursorN, "input");
            int iH6 = V1.H(cursorN, "output");
            int iH7 = V1.H(cursorN, "initial_delay");
            int iH8 = V1.H(cursorN, "interval_duration");
            int iH9 = V1.H(cursorN, "flex_duration");
            int iH10 = V1.H(cursorN, "run_attempt_count");
            int iH11 = V1.H(cursorN, "backoff_policy");
            int iH12 = V1.H(cursorN, "backoff_delay_duration");
            int iH13 = V1.H(cursorN, "last_enqueue_time");
            uVar = uVarA;
            try {
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
                    androidx.work.impl.utils.g gVarH = B2.h(cursorN.getBlob(i19));
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
                return arrayList;
            } catch (Throwable th) {
                th = th;
                cursorN.close();
                uVar.i();
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            uVar = uVarA;
        }
    }

    public N n(String str) {
        androidx.room.u uVarA = androidx.room.u.a(1, "SELECT state FROM workspec WHERE id=?");
        uVarA.g(1, str);
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
        workDatabase_Impl.b();
        Cursor cursorN = W1.N(workDatabase_Impl, uVarA, false);
        try {
            N nF = null;
            if (cursorN.moveToFirst()) {
                Integer numValueOf = cursorN.isNull(0) ? null : Integer.valueOf(cursorN.getInt(0));
                if (numValueOf != null) {
                    nF = B2.f(numValueOf.intValue());
                }
            }
            return nF;
        } finally {
            cursorN.close();
            uVarA.i();
        }
    }

    public q o(String str) {
        androidx.room.u uVar;
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
        int iH12;
        int iH13;
        androidx.room.u uVarA = androidx.room.u.a(1, "SELECT * FROM workspec WHERE id=?");
        uVarA.g(1, str);
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
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
            iH12 = V1.H(cursorN, "backoff_delay_duration");
            iH13 = V1.H(cursorN, "last_enqueue_time");
            uVar = uVarA;
        } catch (Throwable th) {
            th = th;
            uVar = uVarA;
        }
        try {
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
            q qVar = null;
            if (cursorN.moveToFirst()) {
                qVar = new q(cursorN.getString(iH), B2.f(cursorN.getInt(iH2)), cursorN.getString(iH3), cursorN.getString(iH4), C1437k.a(cursorN.getBlob(iH5)), C1437k.a(cursorN.getBlob(iH6)), cursorN.getLong(iH7), cursorN.getLong(iH8), cursorN.getLong(iH9), new C1425f(B2.h(cursorN.getBlob(iH25)), B2.d(cursorN.getInt(iH24)), cursorN.getInt(iH26) != 0, cursorN.getInt(iH27) != 0, cursorN.getInt(iH28) != 0, cursorN.getInt(iH29) != 0, cursorN.getLong(iH30), cursorN.getLong(iH31), B2.a(cursorN.getBlob(iH32))), cursorN.getInt(iH10), B2.c(cursorN.getInt(iH11)), cursorN.getLong(iH12), cursorN.getLong(iH13), cursorN.getLong(iH14), cursorN.getLong(iH15), cursorN.getInt(iH16) != 0, B2.e(cursorN.getInt(iH17)), cursorN.getInt(iH18), cursorN.getInt(iH19), cursorN.getLong(iH20), cursorN.getInt(iH21), cursorN.getInt(iH22), cursorN.isNull(iH23) ? null : cursorN.getString(iH23));
            }
            cursorN.close();
            uVar.i();
            return qVar;
        } catch (Throwable th2) {
            th = th2;
            cursorN.close();
            uVar.i();
            throw th;
        }
    }

    public ArrayList p(String str) {
        androidx.room.u uVarA = androidx.room.u.a(1, "SELECT id, state FROM workspec WHERE id IN (SELECT work_spec_id FROM workname WHERE name=?)");
        uVarA.g(1, str);
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
        workDatabase_Impl.b();
        Cursor cursorN = W1.N(workDatabase_Impl, uVarA, false);
        try {
            ArrayList arrayList = new ArrayList(cursorN.getCount());
            while (cursorN.moveToNext()) {
                String id = cursorN.getString(0);
                N state = B2.f(cursorN.getInt(1));
                Intrinsics.checkNotNullParameter(id, "id");
                Intrinsics.checkNotNullParameter(state, "state");
                o oVar = new o();
                oVar.a = id;
                oVar.b = state;
                arrayList.add(oVar);
            }
            return arrayList;
        } finally {
            cursorN.close();
            uVarA.i();
        }
    }

    public void q(long j, String str) {
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
        workDatabase_Impl.b();
        h hVar = (h) this.l;
        androidx.sqlite.db.framework.i iVarA = hVar.a();
        iVarA.z(1, j);
        iVarA.g(2, str);
        try {
            workDatabase_Impl.c();
            try {
                iVarA.a();
                workDatabase_Impl.p();
            } finally {
                workDatabase_Impl.k();
            }
        } finally {
            hVar.n(iVarA);
        }
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r4v2, types: [java.lang.Object, java.util.Map] */
    public float r(float f) {
        float fK = (Float.isNaN(k()) ? DefinitionKt.NO_Float_VALUE : k()) + f;
        Float fZ = CollectionsKt.Z(h().a.values());
        float fFloatValue = fZ != null ? fZ.floatValue() : Float.NaN;
        Float fX = CollectionsKt.X(h().a.values());
        return kotlin.ranges.l.b(fK, fFloatValue, fX != null ? fX.floatValue() : Float.NaN);
    }

    public float s() {
        if (Float.isNaN(k())) {
            throw new IllegalStateException("The offset was read before being initialized. Did you access the offset in a phase before layout, like effects or composition?");
        }
        return k();
    }

    public void t(int i, String str) {
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
        workDatabase_Impl.b();
        h hVar = (h) this.k;
        androidx.sqlite.db.framework.i iVarA = hVar.a();
        iVarA.g(1, str);
        iVarA.z(2, i);
        try {
            workDatabase_Impl.c();
            try {
                iVarA.a();
                workDatabase_Impl.p();
            } finally {
                workDatabase_Impl.k();
            }
        } finally {
            hVar.n(iVarA);
        }
    }

    public void u(Object obj) {
        ((L0) ((InterfaceC0773a0) this.g)).setValue(obj);
    }

    public void v(Object obj) {
        ((L0) ((InterfaceC0773a0) this.l)).setValue(obj);
    }

    public void w(long j, String str) {
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
        workDatabase_Impl.b();
        h hVar = (h) this.h;
        androidx.sqlite.db.framework.i iVarA = hVar.a();
        iVarA.z(1, j);
        iVarA.g(2, str);
        try {
            workDatabase_Impl.c();
            try {
                iVarA.a();
                workDatabase_Impl.p();
            } finally {
                workDatabase_Impl.k();
            }
        } finally {
            hVar.n(iVarA);
        }
    }

    public void x(String str, C1437k c1437k) {
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
        workDatabase_Impl.b();
        h hVar = (h) this.g;
        androidx.sqlite.db.framework.i iVarA = hVar.a();
        C1437k c1437k2 = C1437k.b;
        iVarA.E(1, AbstractC3390s2.d(c1437k));
        iVarA.g(2, str);
        try {
            workDatabase_Impl.c();
            try {
                iVarA.a();
                workDatabase_Impl.p();
            } finally {
                workDatabase_Impl.k();
            }
        } finally {
            hVar.n(iVarA);
        }
    }

    public void y(N n, String str) {
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
        workDatabase_Impl.b();
        h hVar = (h) this.d;
        androidx.sqlite.db.framework.i iVarA = hVar.a();
        iVarA.z(1, B2.g(n));
        iVarA.g(2, str);
        try {
            workDatabase_Impl.c();
            try {
                iVarA.a();
                workDatabase_Impl.p();
            } finally {
                workDatabase_Impl.k();
            }
        } finally {
            hVar.n(iVarA);
        }
    }

    public void z(int i, String str) {
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.a;
        workDatabase_Impl.b();
        h hVar = (h) this.n;
        androidx.sqlite.db.framework.i iVarA = hVar.a();
        iVarA.z(1, i);
        iVarA.g(2, str);
        try {
            workDatabase_Impl.c();
            try {
                iVarA.a();
                workDatabase_Impl.p();
            } finally {
                workDatabase_Impl.k();
            }
        } finally {
            hVar.n(iVarA);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public t(Enum r1, Function1 function1, Function0 function0, D d, Function1 function12) {
        this.a = function1;
        this.b = (kotlin.jvm.internal.r) function0;
        this.c = d;
        this.d = function12;
        this.e = new E();
        this.f = new androidx.compose.material.r(this);
        this.g = C0776c.z(r1);
        this.h = C0776c.q(new C0648l(this, 4));
        this.i = C0776c.q(new C0648l(this, 2));
        this.j = C0776c.v(Float.NaN);
        C0776c.p(V.f, new C0648l(this, 3));
        this.k = C0776c.v(DefinitionKt.NO_Float_VALUE);
        this.l = C0776c.z(null);
        this.m = C0776c.z(new F(kotlin.collections.V.c()));
        this.n = new androidx.compose.material3.internal.r(this);
    }
}
