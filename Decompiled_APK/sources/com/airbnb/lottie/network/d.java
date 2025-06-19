package com.airbnb.lottie.network;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Resources;
import android.database.SQLException;
import android.hardware.camera2.CameraDevice;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Parcel;
import android.util.Log;
import android.util.TypedValue;
import android.view.View;
import androidx.appcompat.widget.InterfaceC0092j0;
import androidx.camera.camera2.internal.compat.quirk.ExtraCroppingQuirk;
import androidx.compose.animation.core.E;
import androidx.compose.animation.core.G;
import androidx.compose.animation.core.InterfaceC0269u;
import androidx.compose.foundation.lazy.layout.C0442n;
import androidx.compose.ui.unit.n;
import androidx.concurrent.futures.j;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import androidx.core.view.V;
import androidx.room.s;
import androidx.room.util.e;
import com.airbnb.lottie.l;
import com.airbnb.lottie.z;
import com.amazon.aps.shared.metrics.model.k;
import com.android.volley.t;
import com.android.volley.u;
import com.bumptech.glide.load.f;
import com.comscore.streaming.EventType;
import com.facebook.o;
import com.google.android.gms.auth.api.identity.GetSignInIntentRequest;
import com.google.android.gms.common.api.internal.i;
import com.google.android.gms.common.internal.TelemetryData;
import com.google.android.gms.internal.ads.Ev;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_camera.C1;
import com.google.android.gms.internal.p000authapi.h;
import com.google.android.gms.internal.p000authapi.m;
import com.google.android.gms.tasks.Task;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.snackbar.g;
import com.google.firebase.crashlytics.internal.common.x;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.RootActivity;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipInputStream;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class d implements InterfaceC0092j0, androidx.camera.core.impl.utils.futures.c, j, InterfaceC0269u, u, f, Ev, i, InterfaceC1062t {
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ d(int i, boolean z) {
        this.a = i;
    }

    public static void g(androidx.sqlite.db.framework.b bVar) throws SQLException {
        bVar.j("CREATE TABLE IF NOT EXISTS `Dependency` (`work_spec_id` TEXT NOT NULL, `prerequisite_id` TEXT NOT NULL, PRIMARY KEY(`work_spec_id`, `prerequisite_id`), FOREIGN KEY(`work_spec_id`) REFERENCES `WorkSpec`(`id`) ON UPDATE CASCADE ON DELETE CASCADE , FOREIGN KEY(`prerequisite_id`) REFERENCES `WorkSpec`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )");
        bVar.j("CREATE INDEX IF NOT EXISTS `index_Dependency_work_spec_id` ON `Dependency` (`work_spec_id`)");
        bVar.j("CREATE INDEX IF NOT EXISTS `index_Dependency_prerequisite_id` ON `Dependency` (`prerequisite_id`)");
        bVar.j("CREATE TABLE IF NOT EXISTS `WorkSpec` (`id` TEXT NOT NULL, `state` INTEGER NOT NULL, `worker_class_name` TEXT NOT NULL, `input_merger_class_name` TEXT NOT NULL, `input` BLOB NOT NULL, `output` BLOB NOT NULL, `initial_delay` INTEGER NOT NULL, `interval_duration` INTEGER NOT NULL, `flex_duration` INTEGER NOT NULL, `run_attempt_count` INTEGER NOT NULL, `backoff_policy` INTEGER NOT NULL, `backoff_delay_duration` INTEGER NOT NULL, `last_enqueue_time` INTEGER NOT NULL DEFAULT -1, `minimum_retention_duration` INTEGER NOT NULL, `schedule_requested_at` INTEGER NOT NULL, `run_in_foreground` INTEGER NOT NULL, `out_of_quota_policy` INTEGER NOT NULL, `period_count` INTEGER NOT NULL DEFAULT 0, `generation` INTEGER NOT NULL DEFAULT 0, `next_schedule_time_override` INTEGER NOT NULL DEFAULT 9223372036854775807, `next_schedule_time_override_generation` INTEGER NOT NULL DEFAULT 0, `stop_reason` INTEGER NOT NULL DEFAULT -256, `trace_tag` TEXT, `required_network_type` INTEGER NOT NULL, `required_network_request` BLOB NOT NULL DEFAULT x'', `requires_charging` INTEGER NOT NULL, `requires_device_idle` INTEGER NOT NULL, `requires_battery_not_low` INTEGER NOT NULL, `requires_storage_not_low` INTEGER NOT NULL, `trigger_content_update_delay` INTEGER NOT NULL, `trigger_max_content_delay` INTEGER NOT NULL, `content_uri_triggers` BLOB NOT NULL, PRIMARY KEY(`id`))");
        bVar.j("CREATE INDEX IF NOT EXISTS `index_WorkSpec_schedule_requested_at` ON `WorkSpec` (`schedule_requested_at`)");
        bVar.j("CREATE INDEX IF NOT EXISTS `index_WorkSpec_last_enqueue_time` ON `WorkSpec` (`last_enqueue_time`)");
        bVar.j("CREATE TABLE IF NOT EXISTS `WorkTag` (`tag` TEXT NOT NULL, `work_spec_id` TEXT NOT NULL, PRIMARY KEY(`tag`, `work_spec_id`), FOREIGN KEY(`work_spec_id`) REFERENCES `WorkSpec`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )");
        bVar.j("CREATE INDEX IF NOT EXISTS `index_WorkTag_work_spec_id` ON `WorkTag` (`work_spec_id`)");
        bVar.j("CREATE TABLE IF NOT EXISTS `SystemIdInfo` (`work_spec_id` TEXT NOT NULL, `generation` INTEGER NOT NULL DEFAULT 0, `system_id` INTEGER NOT NULL, PRIMARY KEY(`work_spec_id`, `generation`), FOREIGN KEY(`work_spec_id`) REFERENCES `WorkSpec`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )");
        bVar.j("CREATE TABLE IF NOT EXISTS `WorkName` (`name` TEXT NOT NULL, `work_spec_id` TEXT NOT NULL, PRIMARY KEY(`name`, `work_spec_id`), FOREIGN KEY(`work_spec_id`) REFERENCES `WorkSpec`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )");
        bVar.j("CREATE INDEX IF NOT EXISTS `index_WorkName_work_spec_id` ON `WorkName` (`work_spec_id`)");
        bVar.j("CREATE TABLE IF NOT EXISTS `WorkProgress` (`work_spec_id` TEXT NOT NULL, `progress` BLOB NOT NULL, PRIMARY KEY(`work_spec_id`), FOREIGN KEY(`work_spec_id`) REFERENCES `WorkSpec`(`id`) ON UPDATE CASCADE ON DELETE CASCADE )");
        bVar.j("CREATE TABLE IF NOT EXISTS `Preference` (`key` TEXT NOT NULL, `long_value` INTEGER, PRIMARY KEY(`key`))");
        bVar.j("CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)");
        bVar.j("INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, '86254750241babac4b8d52996a675549')");
    }

    public static s o(androidx.sqlite.db.framework.b bVar) {
        HashMap map = new HashMap(2);
        map.put("work_spec_id", new androidx.room.util.a(1, 1, "work_spec_id", "TEXT", null, true));
        map.put("prerequisite_id", new androidx.room.util.a(2, 1, "prerequisite_id", "TEXT", null, true));
        HashSet hashSet = new HashSet(2);
        hashSet.add(new androidx.room.util.b("WorkSpec", "CASCADE", "CASCADE", Arrays.asList("work_spec_id"), Arrays.asList("id")));
        hashSet.add(new androidx.room.util.b("WorkSpec", "CASCADE", "CASCADE", Arrays.asList("prerequisite_id"), Arrays.asList("id")));
        HashSet hashSet2 = new HashSet(2);
        hashSet2.add(new androidx.room.util.d("index_Dependency_work_spec_id", false, Arrays.asList("work_spec_id"), Arrays.asList("ASC")));
        hashSet2.add(new androidx.room.util.d("index_Dependency_prerequisite_id", false, Arrays.asList("prerequisite_id"), Arrays.asList("ASC")));
        e eVar = new e("Dependency", map, hashSet, hashSet2);
        e eVarA = e.a(bVar, "Dependency");
        if (!eVar.equals(eVarA)) {
            return new s(false, "Dependency(androidx.work.impl.model.Dependency).\n Expected:\n" + eVar + "\n Found:\n" + eVarA);
        }
        HashMap map2 = new HashMap(32);
        map2.put("id", new androidx.room.util.a(1, 1, "id", "TEXT", null, true));
        map2.put("state", new androidx.room.util.a(0, 1, "state", "INTEGER", null, true));
        map2.put("worker_class_name", new androidx.room.util.a(0, 1, "worker_class_name", "TEXT", null, true));
        map2.put("input_merger_class_name", new androidx.room.util.a(0, 1, "input_merger_class_name", "TEXT", null, true));
        map2.put("input", new androidx.room.util.a(0, 1, "input", "BLOB", null, true));
        map2.put("output", new androidx.room.util.a(0, 1, "output", "BLOB", null, true));
        map2.put("initial_delay", new androidx.room.util.a(0, 1, "initial_delay", "INTEGER", null, true));
        map2.put("interval_duration", new androidx.room.util.a(0, 1, "interval_duration", "INTEGER", null, true));
        map2.put("flex_duration", new androidx.room.util.a(0, 1, "flex_duration", "INTEGER", null, true));
        map2.put("run_attempt_count", new androidx.room.util.a(0, 1, "run_attempt_count", "INTEGER", null, true));
        map2.put("backoff_policy", new androidx.room.util.a(0, 1, "backoff_policy", "INTEGER", null, true));
        map2.put("backoff_delay_duration", new androidx.room.util.a(0, 1, "backoff_delay_duration", "INTEGER", null, true));
        map2.put("last_enqueue_time", new androidx.room.util.a(0, 1, "last_enqueue_time", "INTEGER", "-1", true));
        map2.put("minimum_retention_duration", new androidx.room.util.a(0, 1, "minimum_retention_duration", "INTEGER", null, true));
        map2.put("schedule_requested_at", new androidx.room.util.a(0, 1, "schedule_requested_at", "INTEGER", null, true));
        map2.put("run_in_foreground", new androidx.room.util.a(0, 1, "run_in_foreground", "INTEGER", null, true));
        map2.put("out_of_quota_policy", new androidx.room.util.a(0, 1, "out_of_quota_policy", "INTEGER", null, true));
        map2.put("period_count", new androidx.room.util.a(0, 1, "period_count", "INTEGER", "0", true));
        map2.put("generation", new androidx.room.util.a(0, 1, "generation", "INTEGER", "0", true));
        map2.put("next_schedule_time_override", new androidx.room.util.a(0, 1, "next_schedule_time_override", "INTEGER", "9223372036854775807", true));
        map2.put("next_schedule_time_override_generation", new androidx.room.util.a(0, 1, "next_schedule_time_override_generation", "INTEGER", "0", true));
        map2.put("stop_reason", new androidx.room.util.a(0, 1, "stop_reason", "INTEGER", "-256", true));
        map2.put("trace_tag", new androidx.room.util.a(0, 1, "trace_tag", "TEXT", null, false));
        map2.put("required_network_type", new androidx.room.util.a(0, 1, "required_network_type", "INTEGER", null, true));
        map2.put("required_network_request", new androidx.room.util.a(0, 1, "required_network_request", "BLOB", "x''", true));
        map2.put("requires_charging", new androidx.room.util.a(0, 1, "requires_charging", "INTEGER", null, true));
        map2.put("requires_device_idle", new androidx.room.util.a(0, 1, "requires_device_idle", "INTEGER", null, true));
        map2.put("requires_battery_not_low", new androidx.room.util.a(0, 1, "requires_battery_not_low", "INTEGER", null, true));
        map2.put("requires_storage_not_low", new androidx.room.util.a(0, 1, "requires_storage_not_low", "INTEGER", null, true));
        map2.put("trigger_content_update_delay", new androidx.room.util.a(0, 1, "trigger_content_update_delay", "INTEGER", null, true));
        map2.put("trigger_max_content_delay", new androidx.room.util.a(0, 1, "trigger_max_content_delay", "INTEGER", null, true));
        map2.put("content_uri_triggers", new androidx.room.util.a(0, 1, "content_uri_triggers", "BLOB", null, true));
        HashSet hashSet3 = new HashSet(0);
        HashSet hashSet4 = new HashSet(2);
        hashSet4.add(new androidx.room.util.d("index_WorkSpec_schedule_requested_at", false, Arrays.asList("schedule_requested_at"), Arrays.asList("ASC")));
        hashSet4.add(new androidx.room.util.d("index_WorkSpec_last_enqueue_time", false, Arrays.asList("last_enqueue_time"), Arrays.asList("ASC")));
        e eVar2 = new e("WorkSpec", map2, hashSet3, hashSet4);
        e eVarA2 = e.a(bVar, "WorkSpec");
        if (!eVar2.equals(eVarA2)) {
            return new s(false, "WorkSpec(androidx.work.impl.model.WorkSpec).\n Expected:\n" + eVar2 + "\n Found:\n" + eVarA2);
        }
        HashMap map3 = new HashMap(2);
        map3.put("tag", new androidx.room.util.a(1, 1, "tag", "TEXT", null, true));
        map3.put("work_spec_id", new androidx.room.util.a(2, 1, "work_spec_id", "TEXT", null, true));
        HashSet hashSet5 = new HashSet(1);
        hashSet5.add(new androidx.room.util.b("WorkSpec", "CASCADE", "CASCADE", Arrays.asList("work_spec_id"), Arrays.asList("id")));
        HashSet hashSet6 = new HashSet(1);
        hashSet6.add(new androidx.room.util.d("index_WorkTag_work_spec_id", false, Arrays.asList("work_spec_id"), Arrays.asList("ASC")));
        e eVar3 = new e("WorkTag", map3, hashSet5, hashSet6);
        e eVarA3 = e.a(bVar, "WorkTag");
        if (!eVar3.equals(eVarA3)) {
            return new s(false, "WorkTag(androidx.work.impl.model.WorkTag).\n Expected:\n" + eVar3 + "\n Found:\n" + eVarA3);
        }
        HashMap map4 = new HashMap(3);
        map4.put("work_spec_id", new androidx.room.util.a(1, 1, "work_spec_id", "TEXT", null, true));
        map4.put("generation", new androidx.room.util.a(2, 1, "generation", "INTEGER", "0", true));
        map4.put("system_id", new androidx.room.util.a(0, 1, "system_id", "INTEGER", null, true));
        HashSet hashSet7 = new HashSet(1);
        hashSet7.add(new androidx.room.util.b("WorkSpec", "CASCADE", "CASCADE", Arrays.asList("work_spec_id"), Arrays.asList("id")));
        e eVar4 = new e("SystemIdInfo", map4, hashSet7, new HashSet(0));
        e eVarA4 = e.a(bVar, "SystemIdInfo");
        if (!eVar4.equals(eVarA4)) {
            return new s(false, "SystemIdInfo(androidx.work.impl.model.SystemIdInfo).\n Expected:\n" + eVar4 + "\n Found:\n" + eVarA4);
        }
        HashMap map5 = new HashMap(2);
        map5.put("name", new androidx.room.util.a(1, 1, "name", "TEXT", null, true));
        map5.put("work_spec_id", new androidx.room.util.a(2, 1, "work_spec_id", "TEXT", null, true));
        HashSet hashSet8 = new HashSet(1);
        hashSet8.add(new androidx.room.util.b("WorkSpec", "CASCADE", "CASCADE", Arrays.asList("work_spec_id"), Arrays.asList("id")));
        HashSet hashSet9 = new HashSet(1);
        hashSet9.add(new androidx.room.util.d("index_WorkName_work_spec_id", false, Arrays.asList("work_spec_id"), Arrays.asList("ASC")));
        e eVar5 = new e("WorkName", map5, hashSet8, hashSet9);
        e eVarA5 = e.a(bVar, "WorkName");
        if (!eVar5.equals(eVarA5)) {
            return new s(false, "WorkName(androidx.work.impl.model.WorkName).\n Expected:\n" + eVar5 + "\n Found:\n" + eVarA5);
        }
        HashMap map6 = new HashMap(2);
        map6.put("work_spec_id", new androidx.room.util.a(1, 1, "work_spec_id", "TEXT", null, true));
        map6.put("progress", new androidx.room.util.a(0, 1, "progress", "BLOB", null, true));
        HashSet hashSet10 = new HashSet(1);
        hashSet10.add(new androidx.room.util.b("WorkSpec", "CASCADE", "CASCADE", Arrays.asList("work_spec_id"), Arrays.asList("id")));
        e eVar6 = new e("WorkProgress", map6, hashSet10, new HashSet(0));
        e eVarA6 = e.a(bVar, "WorkProgress");
        if (!eVar6.equals(eVarA6)) {
            return new s(false, "WorkProgress(androidx.work.impl.model.WorkProgress).\n Expected:\n" + eVar6 + "\n Found:\n" + eVarA6);
        }
        HashMap map7 = new HashMap(2);
        map7.put("key", new androidx.room.util.a(1, 1, "key", "TEXT", null, true));
        map7.put("long_value", new androidx.room.util.a(0, 1, "long_value", "INTEGER", null, false));
        e eVar7 = new e("Preference", map7, new HashSet(0), new HashSet(0));
        e eVarA7 = e.a(bVar, "Preference");
        if (eVar7.equals(eVarA7)) {
            return new s(true, null);
        }
        return new s(false, "Preference(androidx.work.impl.model.Preference).\n Expected:\n" + eVar7 + "\n Found:\n" + eVarA7);
    }

    @Override // com.bumptech.glide.load.f
    public void a(byte[] bArr, Object obj, MessageDigest messageDigest) {
        Integer num = (Integer) obj;
        if (num == null) {
            return;
        }
        messageDigest.update(bArr);
        synchronized (((ByteBuffer) this.b)) {
            ((ByteBuffer) this.b).position(0);
            messageDigest.update(((ByteBuffer) this.b).putInt(num.intValue()).array());
        }
    }

    @Override // com.google.android.gms.common.api.internal.i
    public void accept(Object obj, Object obj2) {
        switch (this.a) {
            case EventType.VIDEO /* 24 */:
                com.google.android.gms.tasks.f fVar = (com.google.android.gms.tasks.f) obj2;
                com.google.android.gms.common.internal.service.a aVar = (com.google.android.gms.common.internal.service.a) ((com.google.android.gms.common.internal.service.c) obj).m();
                Parcel parcelObtain = Parcel.obtain();
                parcelObtain.writeInterfaceToken(aVar.c);
                com.google.android.gms.internal.base.a.b(parcelObtain, (TelemetryData) this.b);
                try {
                    aVar.b.transact(1, parcelObtain, null, 1);
                    parcelObtain.recycle();
                    fVar.b(null);
                    return;
                } catch (Throwable th) {
                    parcelObtain.recycle();
                    throw th;
                }
            default:
                com.google.android.gms.internal.p000authapi.a aVar2 = new com.google.android.gms.internal.p000authapi.a((com.google.android.gms.tasks.f) obj2, 2);
                m mVar = (m) ((com.google.android.gms.internal.p000authapi.d) obj).m();
                GetSignInIntentRequest getSignInIntentRequest = (GetSignInIntentRequest) this.b;
                Parcel parcelX = mVar.X();
                int i = h.a;
                parcelX.writeStrongBinder(aVar2);
                h.c(parcelX, getSignInIntentRequest);
                mVar.f0(3, parcelX);
                return;
        }
    }

    public synchronized void b(String str) {
        c cVar;
        try {
            if (((c) this.b) == null) {
                try {
                    cVar = new c(org.slf4j.d.c(), 17);
                } catch (Throwable unused) {
                    cVar = new c((Object) null, 17);
                }
                this.b = cVar;
            }
            org.slf4j.b bVar = (org.slf4j.b) ((c) this.b).b;
            if (bVar != null) {
                bVar.warn(str);
            } else {
                System.err.println("WARN: ".concat(str));
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public void c(C4950i clazz, Function1 initializer) {
        Intrinsics.checkNotNullParameter(clazz, "clazz");
        Intrinsics.checkNotNullParameter(initializer, "initializer");
        LinkedHashMap linkedHashMap = (LinkedHashMap) this.b;
        if (!linkedHashMap.containsKey(clazz)) {
            linkedHashMap.put(clazz, new androidx.lifecycle.viewmodel.f(clazz, initializer));
            return;
        }
        throw new IllegalArgumentException(("A `initializer` with the same `clazz` has already been added: " + C1.b(clazz) + '.').toString());
    }

    @Override // androidx.concurrent.futures.j
    public Object d(androidx.concurrent.futures.i iVar) {
        androidx.camera.core.impl.utils.futures.d dVar = (androidx.camera.core.impl.utils.futures.d) this.b;
        AbstractC3242q6.h("The result can only set once!", dVar.b == null);
        dVar.b = iVar;
        return "FutureChain[" + dVar + "]";
    }

    public androidx.lifecycle.viewmodel.d e() {
        Collection initializers = ((LinkedHashMap) this.b).values();
        Intrinsics.checkNotNullParameter(initializers, "initializers");
        androidx.lifecycle.viewmodel.f[] fVarArr = (androidx.lifecycle.viewmodel.f[]) initializers.toArray(new androidx.lifecycle.viewmodel.f[0]);
        return new androidx.lifecycle.viewmodel.d((androidx.lifecycle.viewmodel.f[]) Arrays.copyOf(fVarArr, fVarArr.length));
    }

    public JSONObject f() throws JSONException {
        k kVar = (k) this.b;
        try {
            JSONObject eventProperties = new com.google.android.gms.auth.api.signin.internal.h(new com.amazon.aps.shared.metrics.model.d(kVar)).A();
            String eventName = kVar.h != null ? "fe" : kVar.j != null ? "ce" : kVar.g != null ? "be" : kVar.i != null ? "ie" : kVar.k != null ? "vce" : "";
            Intrinsics.checkNotNullParameter("funnel", "eventCategory");
            Intrinsics.checkNotNullParameter(eventName, "eventName");
            Intrinsics.checkNotNullParameter(eventProperties, "eventProperties");
            JSONObject jSONObject = new JSONObject();
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("eventSource", "aps_android_sdk");
            jSONObject2.put("eventTime", System.currentTimeMillis());
            jSONObject2.put("eventName", eventName);
            jSONObject2.put("eventCategory", "funnel");
            jSONObject2.put("eventProperties", eventProperties);
            Unit unit = Unit.a;
            jSONObject.put("Data", jSONObject2);
            jSONObject.put("PartitionKey", System.currentTimeMillis());
            return jSONObject;
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Error building the perf metrics object from builder", e);
            return null;
        }
    }

    @Override // androidx.compose.animation.core.InterfaceC0269u
    public E get(int i) {
        return (G) this.b;
    }

    public void h(byte b) {
        ((Parcel) this.b).writeByte(b);
    }

    public void i(float f) {
        ((Parcel) this.b).writeFloat(f);
    }

    public void j(long j) {
        long jB = androidx.compose.ui.unit.m.b(j);
        byte b = 0;
        if (!n.a(jB, 0L)) {
            if (n.a(jB, 4294967296L)) {
                b = 1;
            } else if (n.a(jB, 8589934592L)) {
                b = 2;
            }
        }
        h(b);
        if (n.a(androidx.compose.ui.unit.m.b(j), 0L)) {
            return;
        }
        i(androidx.compose.ui.unit.m.c(j));
    }

    public z k(Context context, String str, InputStream inputStream, String str2, String str3) {
        z zVarH;
        b bVar;
        if (str2 == null) {
            str2 = "application/json";
        }
        boolean zContains = str2.contains("application/zip");
        c cVar = (c) this.b;
        if (zContains || str2.contains("application/x-zip") || str2.contains("application/x-zip-compressed") || str.split("\\?")[0].endsWith(".lottie")) {
            com.airbnb.lottie.utils.c.a();
            b bVar2 = b.ZIP;
            zVarH = str3 != null ? l.h(context, new ZipInputStream(new FileInputStream(cVar.A(str, inputStream, bVar2))), str) : l.h(context, new ZipInputStream(inputStream), null);
            bVar = bVar2;
        } else if (str2.contains("application/gzip") || str2.contains("application/x-gzip") || str.split("\\?")[0].endsWith(".tgs")) {
            com.airbnb.lottie.utils.c.a();
            bVar = b.GZIP;
            zVarH = str3 != null ? l.d(new GZIPInputStream(new FileInputStream(cVar.A(str, inputStream, bVar))), str) : l.d(new GZIPInputStream(inputStream), null);
        } else {
            com.airbnb.lottie.utils.c.a();
            bVar = b.JSON;
            zVarH = str3 != null ? l.d(new FileInputStream(cVar.A(str, inputStream, bVar).getAbsolutePath()), str) : l.d(inputStream, null);
        }
        if (str3 != null && zVarH.a != null) {
            File file = new File(cVar.x(), c.p(str, bVar, true));
            File file2 = new File(file.getAbsolutePath().replace(".temp", ""));
            boolean zRenameTo = file.renameTo(file2);
            file2.toString();
            com.airbnb.lottie.utils.c.a();
            if (!zRenameTo) {
                com.airbnb.lottie.utils.c.b("Unable to rename cache file " + file.getAbsolutePath() + " to " + file2.getAbsolutePath() + ".");
            }
        }
        return zVarH;
    }

    public void l() throws Resources.NotFoundException {
        TypedValue typedValue = new TypedValue();
        Resources.Theme currentTheme = ((RootActivity) this.b).getTheme();
        currentTheme.resolveAttribute(R.attr.windowSplashScreenBackground, typedValue, true);
        if (currentTheme.resolveAttribute(R.attr.windowSplashScreenAnimatedIcon, typedValue, true)) {
            currentTheme.getDrawable(typedValue.resourceId);
        }
        currentTheme.resolveAttribute(R.attr.splashScreenIconSize, typedValue, true);
        Intrinsics.checkNotNullExpressionValue(currentTheme, "currentTheme");
        q(currentTheme, typedValue);
    }

    public void m(View view) {
        if (view.getParent() != null) {
            view.setVisibility(8);
        }
        ((g) this.b).a(0);
    }

    public void n(com.google.android.datatransport.cct.internal.s sVar, Thread thread, Throwable th) {
        Task taskF;
        com.google.firebase.crashlytics.internal.common.m mVar = (com.google.firebase.crashlytics.internal.common.m) this.b;
        synchronized (mVar) {
            Objects.toString(th);
            thread.getName();
            Log.isLoggable("FirebaseCrashlytics", 3);
            long jCurrentTimeMillis = System.currentTimeMillis();
            com.google.firebase.crashlytics.internal.concurrency.b bVar = mVar.e.a;
            com.google.firebase.crashlytics.internal.common.k kVar = new com.google.firebase.crashlytics.internal.common.k(mVar, jCurrentTimeMillis, th, thread, sVar);
            synchronized (bVar.b) {
                taskF = bVar.c.f(bVar.a, new com.google.android.material.search.a(kVar, 8));
                bVar.c = taskF;
            }
            try {
                x.a(taskF);
            } catch (TimeoutException unused) {
                Log.e("FirebaseCrashlytics", "Cannot send reports. Timed out while fetching settings.", null);
            } catch (Exception e) {
                Log.e("FirebaseCrashlytics", "Error handling uncaught exception", e);
            }
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        ((androidx.camera.core.G) this.b).close();
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public /* bridge */ /* synthetic */ void onSuccess(Object obj) {
    }

    public void p(com.android.volley.l lVar, t tVar, com.google.common.util.concurrent.d dVar) {
        lVar.markDelivered();
        lVar.addMarker("post-response");
        ((androidx.core.provider.j) this.b).execute(new androidx.core.provider.k(lVar, tVar, dVar, 4));
    }

    public void q(Resources.Theme currentTheme, TypedValue typedValue) {
        int i;
        Intrinsics.checkNotNullParameter(currentTheme, "currentTheme");
        Intrinsics.checkNotNullParameter(typedValue, "typedValue");
        if (!currentTheme.resolveAttribute(R.attr.postSplashScreenTheme, typedValue, true) || (i = typedValue.resourceId) == 0) {
            return;
        }
        ((RootActivity) this.b).setTheme(i);
    }

    public void r(String str) {
        if (str == null) {
            return;
        }
        ((k) this.b).c = str;
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) {
        AppBarLayout appBarLayout = (AppBarLayout) this.b;
        WeakHashMap weakHashMap = V.a;
        D0 d02 = appBarLayout.getFitsSystemWindows() ? d0 : null;
        if (!Objects.equals(appBarLayout.g, d02)) {
            appBarLayout.g = d02;
            appBarLayout.setWillNotDraw(!(appBarLayout.v != null && appBarLayout.getTopInset() > 0));
            appBarLayout.requestLayout();
        }
        return d0;
    }

    @Override // com.google.android.gms.internal.ads.Ev
    /* renamed from: zza */
    public com.google.common.util.concurrent.e mo19zza() {
        com.google.android.gms.ads.nonagon.signalgeneration.i iVar = (com.google.android.gms.ads.nonagon.signalgeneration.i) this.b;
        return (com.google.common.util.concurrent.e) iVar.e4(iVar.c, null, "BANNER", null, null, 0, null, new Bundle(), null).b.zzb();
    }

    public /* synthetic */ d(com.google.android.gms.internal.p000authapi.b bVar, GetSignInIntentRequest getSignInIntentRequest) {
        this.a = 25;
        this.b = getSignInIntentRequest;
    }

    public /* synthetic */ d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public d(c cVar, com.google.mlkit.common.sdkinternal.model.a aVar) {
        this.a = 0;
        this.b = cVar;
    }

    public d(Handler handler) {
        this.a = 18;
        this.b = new androidx.core.provider.j(handler, 1);
    }

    public d(CameraDevice cameraDevice, Handler handler) {
        this.a = 4;
        if (Build.VERSION.SDK_INT >= 28) {
            cameraDevice.getClass();
            this.b = new androidx.camera.camera2.internal.compat.n(cameraDevice, null);
        } else {
            this.b = new androidx.camera.camera2.internal.compat.m(cameraDevice, new com.google.android.gms.auth.api.signin.internal.h(handler, 4));
        }
    }

    public d(int i) {
        this.a = i;
        switch (i) {
            case 9:
                this.b = new androidx.compose.runtime.collection.b(new C0442n[16]);
                break;
            case 10:
            case 11:
            case 12:
            case 15:
            case 16:
            case 18:
            default:
                this.b = (ExtraCroppingQuirk) androidx.camera.camera2.internal.compat.quirk.b.a.b(ExtraCroppingQuirk.class);
                break;
            case 13:
                this.b = new AtomicBoolean(false);
                break;
            case 14:
                this.b = new LinkedHashMap();
                break;
            case 17:
                k kVar = new k();
                kVar.b = null;
                this.b = kVar;
                break;
            case 19:
                this.b = new ArrayDeque();
                break;
            case 20:
                this.b = ByteBuffer.allocate(4);
                break;
            case 21:
                SharedPreferences sharedPreferences = o.a().getSharedPreferences("com.facebook.AuthenticationTokenManager.SharedPreferences", 0);
                Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getApplicationContext()\n…ME, Context.MODE_PRIVATE)");
                Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
                this.b = sharedPreferences;
                break;
        }
    }

    public d(RootActivity activity) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(activity, "activity");
        this.b = activity;
    }

    public d(float f, float f2) {
        this.a = 8;
        this.b = new G(f, f2, 0.01f);
    }
}
