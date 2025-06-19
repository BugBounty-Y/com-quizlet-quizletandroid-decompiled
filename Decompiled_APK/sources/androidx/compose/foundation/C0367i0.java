package androidx.compose.foundation;

import android.database.Cursor;
import androidx.compose.ui.text.C0995g;
import androidx.work.C1425f;
import androidx.work.C1437k;
import androidx.work.impl.WorkDatabase;
import androidx.work.impl.WorkDatabase_Impl;
import com.google.android.gms.internal.mlkit_vision_camera.B2;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.i0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0367i0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0367i0(String str, int i) {
        super(1);
        this.a = i;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String str = this.b;
        switch (this.a) {
            case 0:
                androidx.compose.ui.semantics.v vVar = (androidx.compose.ui.semantics.v) obj;
                androidx.compose.ui.semantics.t.e(vVar, str);
                androidx.compose.ui.semantics.t.h(vVar, 5);
                return Unit.a;
            case 1:
                androidx.compose.ui.semantics.v vVar2 = (androidx.compose.ui.semantics.v) obj;
                androidx.compose.ui.semantics.t.e(vVar2, str);
                androidx.compose.ui.semantics.t.h(vVar2, 5);
                return Unit.a;
            case 2:
                kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
                androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.d;
                kotlin.reflect.n nVar = androidx.compose.ui.semantics.t.a[2];
                uVar.a((androidx.compose.ui.semantics.v) obj, str);
                return Unit.a;
            case 3:
                kotlin.reflect.n[] nVarArr2 = androidx.compose.ui.semantics.t.a;
                androidx.compose.ui.semantics.u uVar2 = androidx.compose.ui.semantics.r.d;
                kotlin.reflect.n nVar2 = androidx.compose.ui.semantics.t.a[2];
                uVar2.a((androidx.compose.ui.semantics.v) obj, str);
                return Unit.a;
            case 4:
                androidx.compose.ui.semantics.v vVar3 = (androidx.compose.ui.semantics.v) obj;
                androidx.compose.ui.semantics.t.j(vVar3, new C0995g(6, str, null));
                androidx.compose.ui.semantics.t.h(vVar3, 0);
                return Unit.a;
            case 5:
                androidx.compose.ui.semantics.v vVar4 = (androidx.compose.ui.semantics.v) obj;
                androidx.compose.ui.semantics.t.f(vVar4);
                androidx.compose.ui.semantics.t.e(vVar4, str);
                return Unit.a;
            case 6:
                androidx.compose.ui.semantics.v vVar5 = (androidx.compose.ui.semantics.v) obj;
                androidx.compose.ui.semantics.t.j(vVar5, new C0995g(6, str, null));
                androidx.compose.ui.semantics.t.h(vVar5, 0);
                return Unit.a;
            case 7:
                androidx.compose.ui.semantics.v vVar6 = (androidx.compose.ui.semantics.v) obj;
                androidx.compose.ui.semantics.t.e(vVar6, str);
                androidx.compose.ui.semantics.t.h(vVar6, 5);
                return Unit.a;
            case 8:
                androidx.compose.ui.semantics.v vVar7 = (androidx.compose.ui.semantics.v) obj;
                kotlin.reflect.n[] nVarArr3 = androidx.compose.ui.semantics.t.a;
                androidx.compose.ui.semantics.u uVar3 = androidx.compose.ui.semantics.r.d;
                kotlin.reflect.n[] nVarArr4 = androidx.compose.ui.semantics.t.a;
                kotlin.reflect.n nVar3 = nVarArr4[2];
                uVar3.a(vVar7, str);
                androidx.compose.ui.semantics.u uVar4 = androidx.compose.ui.semantics.r.n;
                kotlin.reflect.n nVar4 = nVarArr4[9];
                uVar4.a(vVar7, Float.valueOf(DefinitionKt.NO_Float_VALUE));
                return Unit.a;
            case 9:
                kotlin.reflect.n[] nVarArr5 = androidx.compose.ui.semantics.t.a;
                ((androidx.compose.ui.semantics.k) ((androidx.compose.ui.semantics.v) obj)).b(androidx.compose.ui.semantics.r.D, str);
                return Unit.a;
            case 10:
                androidx.compose.ui.semantics.t.e((androidx.compose.ui.semantics.v) obj, str);
                return Unit.a;
            case 11:
                ((androidx.glance.semantics.a) obj).a.put(androidx.glance.semantics.d.a, kotlin.collections.A.b(str));
                return Unit.a;
            default:
                WorkDatabase db = (WorkDatabase) obj;
                Intrinsics.checkNotNullParameter(db, "db");
                androidx.camera.camera2.internal.s0 s0Var = androidx.work.impl.model.q.z;
                androidx.work.impl.model.t tVarU = db.u();
                tVarU.getClass();
                androidx.room.u uVarA = androidx.room.u.a(1, "SELECT id, state, output, run_attempt_count, generation, required_network_type, required_network_request, requires_charging, requires_device_idle, requires_battery_not_low, requires_storage_not_low, trigger_content_update_delay, trigger_max_content_delay, content_uri_triggers, initial_delay, interval_duration, flex_duration, backoff_policy, backoff_delay_duration, last_enqueue_time, period_count, next_schedule_time_override, stop_reason FROM workspec WHERE id IN (SELECT work_spec_id FROM workname WHERE name=?)");
                uVarA.g(1, str);
                WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) tVarU.a;
                workDatabase_Impl.b();
                workDatabase_Impl.c();
                try {
                    Cursor cursorN = W1.N(workDatabase_Impl, uVarA, true);
                    try {
                        HashMap map = new HashMap();
                        HashMap map2 = new HashMap();
                        while (cursorN.moveToNext()) {
                            String string = cursorN.getString(0);
                            if (!map.containsKey(string)) {
                                map.put(string, new ArrayList());
                            }
                            String string2 = cursorN.getString(0);
                            if (!map2.containsKey(string2)) {
                                map2.put(string2, new ArrayList());
                            }
                        }
                        cursorN.moveToPosition(-1);
                        tVarU.b(map);
                        tVarU.a(map2);
                        ArrayList arrayList = new ArrayList(cursorN.getCount());
                        while (cursorN.moveToNext()) {
                            String string3 = cursorN.getString(0);
                            androidx.work.N nF = B2.f(cursorN.getInt(1));
                            C1437k c1437kA = C1437k.a(cursorN.getBlob(2));
                            int i = cursorN.getInt(3);
                            int i2 = cursorN.getInt(4);
                            arrayList.add(new androidx.work.impl.model.p(string3, nF, c1437kA, cursorN.getLong(14), cursorN.getLong(15), cursorN.getLong(16), new C1425f(B2.h(cursorN.getBlob(6)), B2.d(cursorN.getInt(5)), cursorN.getInt(7) != 0, cursorN.getInt(8) != 0, cursorN.getInt(9) != 0, cursorN.getInt(10) != 0, cursorN.getLong(11), cursorN.getLong(12), B2.a(cursorN.getBlob(13))), i, B2.c(cursorN.getInt(17)), cursorN.getLong(18), cursorN.getLong(19), cursorN.getInt(20), i2, cursorN.getLong(21), cursorN.getInt(22), (ArrayList) map.get(cursorN.getString(0)), (ArrayList) map2.get(cursorN.getString(0))));
                        }
                        workDatabase_Impl.p();
                        cursorN.close();
                        uVarA.i();
                        workDatabase_Impl.k();
                        Object objMo0apply = s0Var.mo0apply(arrayList);
                        Intrinsics.checkNotNullExpressionValue(objMo0apply, "WORK_INFO_MAPPER.apply(d…kStatusPojoForName(name))");
                        return (List) objMo0apply;
                    } catch (Throwable th) {
                        cursorN.close();
                        uVarA.i();
                        throw th;
                    }
                } catch (Throwable th2) {
                    workDatabase_Impl.k();
                    throw th2;
                }
        }
    }
}
