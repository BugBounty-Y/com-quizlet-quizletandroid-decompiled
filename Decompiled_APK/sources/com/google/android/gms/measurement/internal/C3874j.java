package com.google.android.gms.measurement.internal;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.os.SystemClock;
import android.text.TextUtils;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.measurement.C2964a1;
import com.google.android.gms.internal.measurement.C2969b1;
import com.google.android.gms.internal.measurement.C2974c1;
import com.google.android.gms.internal.measurement.E3;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/* renamed from: com.google.android.gms.measurement.internal.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3874j extends m1 {
    public static final String[] g = {"last_bundled_timestamp", "ALTER TABLE events ADD COLUMN last_bundled_timestamp INTEGER;", "last_bundled_day", "ALTER TABLE events ADD COLUMN last_bundled_day INTEGER;", "last_sampled_complex_event_id", "ALTER TABLE events ADD COLUMN last_sampled_complex_event_id INTEGER;", "last_sampling_rate", "ALTER TABLE events ADD COLUMN last_sampling_rate INTEGER;", "last_exempt_from_sampling", "ALTER TABLE events ADD COLUMN last_exempt_from_sampling INTEGER;", "current_session_count", "ALTER TABLE events ADD COLUMN current_session_count INTEGER;"};
    public static final String[] h = {"associated_row_id", "ALTER TABLE upload_queue ADD COLUMN associated_row_id INTEGER;", "last_upload_timestamp", "ALTER TABLE upload_queue ADD COLUMN last_upload_timestamp INTEGER;"};
    public static final String[] i = {"origin", "ALTER TABLE user_attributes ADD COLUMN origin TEXT;"};
    public static final String[] j = {"app_version", "ALTER TABLE apps ADD COLUMN app_version TEXT;", "app_store", "ALTER TABLE apps ADD COLUMN app_store TEXT;", "gmp_version", "ALTER TABLE apps ADD COLUMN gmp_version INTEGER;", "dev_cert_hash", "ALTER TABLE apps ADD COLUMN dev_cert_hash INTEGER;", "measurement_enabled", "ALTER TABLE apps ADD COLUMN measurement_enabled INTEGER;", "last_bundle_start_timestamp", "ALTER TABLE apps ADD COLUMN last_bundle_start_timestamp INTEGER;", "day", "ALTER TABLE apps ADD COLUMN day INTEGER;", "daily_public_events_count", "ALTER TABLE apps ADD COLUMN daily_public_events_count INTEGER;", "daily_events_count", "ALTER TABLE apps ADD COLUMN daily_events_count INTEGER;", "daily_conversions_count", "ALTER TABLE apps ADD COLUMN daily_conversions_count INTEGER;", "remote_config", "ALTER TABLE apps ADD COLUMN remote_config BLOB;", "config_fetched_time", "ALTER TABLE apps ADD COLUMN config_fetched_time INTEGER;", "failed_config_fetch_time", "ALTER TABLE apps ADD COLUMN failed_config_fetch_time INTEGER;", "app_version_int", "ALTER TABLE apps ADD COLUMN app_version_int INTEGER;", "firebase_instance_id", "ALTER TABLE apps ADD COLUMN firebase_instance_id TEXT;", "daily_error_events_count", "ALTER TABLE apps ADD COLUMN daily_error_events_count INTEGER;", "daily_realtime_events_count", "ALTER TABLE apps ADD COLUMN daily_realtime_events_count INTEGER;", "health_monitor_sample", "ALTER TABLE apps ADD COLUMN health_monitor_sample TEXT;", "android_id", "ALTER TABLE apps ADD COLUMN android_id INTEGER;", "adid_reporting_enabled", "ALTER TABLE apps ADD COLUMN adid_reporting_enabled INTEGER;", "ssaid_reporting_enabled", "ALTER TABLE apps ADD COLUMN ssaid_reporting_enabled INTEGER;", "admob_app_id", "ALTER TABLE apps ADD COLUMN admob_app_id TEXT;", "linked_admob_app_id", "ALTER TABLE apps ADD COLUMN linked_admob_app_id TEXT;", "dynamite_version", "ALTER TABLE apps ADD COLUMN dynamite_version INTEGER;", "safelisted_events", "ALTER TABLE apps ADD COLUMN safelisted_events TEXT;", "ga_app_id", "ALTER TABLE apps ADD COLUMN ga_app_id TEXT;", "config_last_modified_time", "ALTER TABLE apps ADD COLUMN config_last_modified_time TEXT;", "e_tag", "ALTER TABLE apps ADD COLUMN e_tag TEXT;", "session_stitching_token", "ALTER TABLE apps ADD COLUMN session_stitching_token TEXT;", "sgtm_upload_enabled", "ALTER TABLE apps ADD COLUMN sgtm_upload_enabled INTEGER;", "target_os_version", "ALTER TABLE apps ADD COLUMN target_os_version INTEGER;", "session_stitching_token_hash", "ALTER TABLE apps ADD COLUMN session_stitching_token_hash INTEGER;", "ad_services_version", "ALTER TABLE apps ADD COLUMN ad_services_version INTEGER;", "unmatched_first_open_without_ad_id", "ALTER TABLE apps ADD COLUMN unmatched_first_open_without_ad_id INTEGER;", "npa_metadata_value", "ALTER TABLE apps ADD COLUMN npa_metadata_value INTEGER;", "attribution_eligibility_status", "ALTER TABLE apps ADD COLUMN attribution_eligibility_status INTEGER;", "sgtm_preview_key", "ALTER TABLE apps ADD COLUMN sgtm_preview_key TEXT;", "dma_consent_state", "ALTER TABLE apps ADD COLUMN dma_consent_state INTEGER;", "daily_realtime_dcu_count", "ALTER TABLE apps ADD COLUMN daily_realtime_dcu_count INTEGER;", "bundle_delivery_index", "ALTER TABLE apps ADD COLUMN bundle_delivery_index INTEGER;", "serialized_npa_metadata", "ALTER TABLE apps ADD COLUMN serialized_npa_metadata TEXT;", "unmatched_pfo", "ALTER TABLE apps ADD COLUMN unmatched_pfo INTEGER;", "unmatched_uwa", "ALTER TABLE apps ADD COLUMN unmatched_uwa INTEGER;", "ad_campaign_info", "ALTER TABLE apps ADD COLUMN ad_campaign_info BLOB;", "daily_registered_triggers_count", "ALTER TABLE apps ADD COLUMN daily_registered_triggers_count INTEGER;", "client_upload_eligibility", "ALTER TABLE apps ADD COLUMN client_upload_eligibility INTEGER;"};
    public static final String[] k = {"realtime", "ALTER TABLE raw_events ADD COLUMN realtime INTEGER;"};
    public static final String[] l = {"has_realtime", "ALTER TABLE queue ADD COLUMN has_realtime INTEGER;", "retry_count", "ALTER TABLE queue ADD COLUMN retry_count INTEGER;"};
    public static final String[] m = {"session_scoped", "ALTER TABLE event_filters ADD COLUMN session_scoped BOOLEAN;"};
    public static final String[] n = {"session_scoped", "ALTER TABLE property_filters ADD COLUMN session_scoped BOOLEAN;"};
    public static final String[] o = {"previous_install_count", "ALTER TABLE app2 ADD COLUMN previous_install_count INTEGER;"};
    public static final String[] p = {"consent_source", "ALTER TABLE consent_settings ADD COLUMN consent_source INTEGER;", "dma_consent_settings", "ALTER TABLE consent_settings ADD COLUMN dma_consent_settings TEXT;", "storage_consent_at_bundling", "ALTER TABLE consent_settings ADD COLUMN storage_consent_at_bundling TEXT;"};
    public static final String[] q = {"idempotent", "CREATE INDEX IF NOT EXISTS trigger_uris_index ON trigger_uris (app_id);"};
    public final C3872i e;
    public final androidx.compose.foundation.gestures.l1 f;

    public C3874j(r1 r1Var) {
        super(r1Var);
        this.f = new androidx.compose.foundation.gestures.l1(((Y) this.b).n);
        ((Y) this.b).getClass();
        this.e = new C3872i(this, ((Y) this.b).a);
    }

    public static final String B0(ArrayList arrayList) {
        return arrayList.isEmpty() ? "" : android.support.v4.media.session.a.B(" AND (upload_type IN (", TextUtils.join(", ", arrayList), "))");
    }

    public static final void I0(ContentValues contentValues, Object obj) {
        com.google.android.gms.common.internal.u.e("value");
        com.google.android.gms.common.internal.u.h(obj);
        if (obj instanceof String) {
            contentValues.put("value", (String) obj);
        } else if (obj instanceof Long) {
            contentValues.put("value", (Long) obj);
        } else {
            if (!(obj instanceof Double)) {
                throw new IllegalArgumentException("Invalid value type");
            }
            contentValues.put("value", (Double) obj);
        }
    }

    public final void A0(ContentValues contentValues) {
        Y y = (Y) this.b;
        try {
            SQLiteDatabase sQLiteDatabaseO0 = O0();
            if (contentValues.getAsString("app_id") == null) {
                I i2 = y.i;
                Y.k(i2);
                i2.i.g("Value of the primary key is not set.", I.a0("app_id"));
            } else if (sQLiteDatabaseO0.update("consent_settings", contentValues, "app_id = ?", new String[]{r4}) == 0 && sQLiteDatabaseO0.insertWithOnConflict("consent_settings", null, contentValues, 5) == -1) {
                I i3 = y.i;
                Y.k(i3);
                i3.g.h("Failed to insert/update table (got -1). key", I.a0("consent_settings"), I.a0("app_id"));
            }
        } catch (SQLiteException e) {
            I i4 = y.i;
            Y.k(i4);
            i4.g.i("Error storing into table. key", I.a0("consent_settings"), I.a0("app_id"), e);
        }
    }

    public final void C0(String str, zzov zzovVar) {
        S();
        T();
        com.google.android.gms.common.internal.u.e(str);
        Y y = (Y) this.b;
        y.n.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        C3891s c3891s = AbstractC3893t.u0;
        long jLongValue = jCurrentTimeMillis - ((Long) c3891s.a(null)).longValue();
        long j2 = zzovVar.b;
        I i2 = y.i;
        if (j2 < jLongValue || j2 > ((Long) c3891s.a(null)).longValue() + jCurrentTimeMillis) {
            Y.k(i2);
            i2.j.i("Storing trigger URI outside of the max retention time span. appId, now, timestamp", I.a0(str), Long.valueOf(jCurrentTimeMillis), Long.valueOf(j2));
        }
        Y.k(i2);
        i2.o.f("Saving trigger URI");
        ContentValues contentValues = new ContentValues();
        contentValues.put("app_id", str);
        contentValues.put("trigger_uri", zzovVar.a);
        contentValues.put("source", Integer.valueOf(zzovVar.c));
        contentValues.put("timestamp_millis", Long.valueOf(j2));
        try {
            if (O0().insert("trigger_uris", null, contentValues) == -1) {
                Y.k(i2);
                i2.g.g("Failed to insert trigger URI (got -1). appId", I.a0(str));
            }
        } catch (SQLiteException e) {
            Y.k(i2);
            i2.g.h("Error storing trigger URI. appId", I.a0(str), e);
        }
    }

    public final boolean D0() {
        return ((Y) this.b).a.getDatabasePath("google_app_measurement.db").exists();
    }

    public final void E0(String str, Long l2, long j2, com.google.android.gms.internal.measurement.U0 u0) {
        S();
        T();
        com.google.android.gms.common.internal.u.h(u0);
        com.google.android.gms.common.internal.u.e(str);
        byte[] bArrC = u0.c();
        Y y = (Y) this.b;
        I i2 = y.i;
        I i3 = y.i;
        Y.k(i2);
        i2.o.h("Saving complex main event, appId, data size", y.m.d(str), Integer.valueOf(bArrC.length));
        ContentValues contentValues = new ContentValues();
        contentValues.put("app_id", str);
        contentValues.put("event_id", l2);
        contentValues.put("children_to_process", Long.valueOf(j2));
        contentValues.put("main_event", bArrC);
        try {
            if (O0().insertWithOnConflict("main_event_params", null, contentValues, 5) == -1) {
                Y.k(i3);
                i3.g.g("Failed to insert complex main event (got -1). appId", I.a0(str));
            }
        } catch (SQLiteException e) {
            Y.k(i3);
            i3.g.h("Error storing complex main event. appId", I.a0(str), e);
        }
    }

    public final boolean F0(zzai zzaiVar) {
        S();
        T();
        String str = zzaiVar.a;
        com.google.android.gms.common.internal.u.h(str);
        v1 v1VarY0 = Y0(str, zzaiVar.c.b);
        Y y = (Y) this.b;
        if (v1VarY0 == null) {
            long jJ0 = J0("SELECT COUNT(1) FROM conditional_properties WHERE app_id=?", new String[]{str});
            y.getClass();
            if (jJ0 >= 1000) {
                return false;
            }
        }
        ContentValues contentValues = new ContentValues();
        contentValues.put("app_id", str);
        contentValues.put("origin", zzaiVar.b);
        contentValues.put("name", zzaiVar.c.b);
        Object objA = zzaiVar.c.a();
        com.google.android.gms.common.internal.u.h(objA);
        I0(contentValues, objA);
        contentValues.put("active", Boolean.valueOf(zzaiVar.e));
        contentValues.put("trigger_event_name", zzaiVar.f);
        contentValues.put("trigger_timeout", Long.valueOf(zzaiVar.h));
        x1 x1Var = y.l;
        I i2 = y.i;
        Y.h(x1Var);
        contentValues.put("timed_out_event", x1.R0(zzaiVar.g));
        contentValues.put("creation_timestamp", Long.valueOf(zzaiVar.d));
        Y.h(y.l);
        contentValues.put("triggered_event", x1.R0(zzaiVar.i));
        contentValues.put("triggered_timestamp", Long.valueOf(zzaiVar.c.c));
        contentValues.put("time_to_live", Long.valueOf(zzaiVar.j));
        contentValues.put("expired_event", x1.R0(zzaiVar.k));
        try {
            if (O0().insertWithOnConflict("conditional_properties", null, contentValues, 5) != -1) {
                return true;
            }
            Y.k(i2);
            i2.g.g("Failed to insert/update conditional user property (got -1)", I.a0(str));
            return true;
        } catch (SQLiteException e) {
            Y.k(i2);
            i2.g.h("Error storing conditional user property", I.a0(str), e);
            return true;
        }
    }

    public final boolean G0(v1 v1Var) {
        S();
        T();
        String str = v1Var.a;
        String str2 = v1Var.c;
        v1 v1VarY0 = Y0(str, str2);
        Y y = (Y) this.b;
        String str3 = v1Var.b;
        if (v1VarY0 == null) {
            if (x1.M0(str2)) {
                if (J0("select count(1) from user_attributes where app_id=? and name not like '!_%' escape '!'", new String[]{str}) >= Math.max(Math.min(y.g.Y(str, AbstractC3893t.U), 100), 25)) {
                    return false;
                }
            } else if (!"_npa".equals(str2)) {
                long jJ0 = J0("select count(1) from user_attributes where app_id=? and origin=? AND name like '!_%' escape '!'", new String[]{str, str3});
                y.getClass();
                if (jJ0 >= 25) {
                    return false;
                }
            }
        }
        ContentValues contentValues = new ContentValues();
        contentValues.put("app_id", str);
        contentValues.put("origin", str3);
        contentValues.put("name", str2);
        contentValues.put("set_timestamp", Long.valueOf(v1Var.d));
        I0(contentValues, v1Var.e);
        try {
            if (O0().insertWithOnConflict("user_attributes", null, contentValues, 5) != -1) {
                return true;
            }
            I i2 = y.i;
            Y.k(i2);
            i2.g.g("Failed to insert/update user property (got -1). appId", I.a0(str));
            return true;
        } catch (SQLiteException e) {
            I i3 = y.i;
            Y.k(i3);
            i3.g.h("Error storing user property. appId", I.a0(str), e);
            return true;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x00dd A[Catch: all -> 0x006f, SQLiteException -> 0x0072, TryCatch #3 {SQLiteException -> 0x0072, blocks: (B:19:0x0067, B:40:0x00b8, B:42:0x00dd, B:43:0x00ef, B:44:0x00f3, B:45:0x0103, B:47:0x0109, B:48:0x0119, B:50:0x0122, B:53:0x0136, B:55:0x0153, B:56:0x015c, B:58:0x0167, B:63:0x01a3, B:62:0x0192, B:66:0x01aa, B:52:0x012f, B:68:0x01bc), top: B:84:0x0067 }] */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00ef A[Catch: all -> 0x006f, SQLiteException -> 0x0072, TRY_LEAVE, TryCatch #3 {SQLiteException -> 0x0072, blocks: (B:19:0x0067, B:40:0x00b8, B:42:0x00dd, B:43:0x00ef, B:44:0x00f3, B:45:0x0103, B:47:0x0109, B:48:0x0119, B:50:0x0122, B:53:0x0136, B:55:0x0153, B:56:0x015c, B:58:0x0167, B:63:0x01a3, B:62:0x0192, B:66:0x01aa, B:52:0x012f, B:68:0x01bc), top: B:84:0x0067 }] */
    /* JADX WARN: Removed duplicated region for block: B:74:0x01e1 A[DONT_GENERATE] */
    /* JADX WARN: Removed duplicated region for block: B:92:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void H0(java.lang.String r20, long r21, long r23, androidx.work.impl.background.greedy.d r25) {
        /*
            Method dump skipped, instructions count: 491
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.H0(java.lang.String, long, long, androidx.work.impl.background.greedy.d):void");
    }

    public final long J0(String str, String[] strArr) {
        Cursor cursor = null;
        try {
            try {
                Cursor cursorRawQuery = O0().rawQuery(str, strArr);
                if (!cursorRawQuery.moveToFirst()) {
                    throw new SQLiteException("Database returned empty set");
                }
                long j2 = cursorRawQuery.getLong(0);
                cursorRawQuery.close();
                return j2;
            } catch (SQLiteException e) {
                I i2 = ((Y) this.b).i;
                Y.k(i2);
                i2.g.h("Database error", str, e);
                throw e;
            }
        } catch (Throwable th) {
            if (0 != 0) {
                cursor.close();
            }
            throw th;
        }
    }

    public final long K0(String str, String[] strArr, long j2) {
        Cursor cursorRawQuery = null;
        try {
            try {
                cursorRawQuery = O0().rawQuery(str, strArr);
                if (cursorRawQuery.moveToFirst()) {
                    j2 = cursorRawQuery.getLong(0);
                }
                cursorRawQuery.close();
                return j2;
            } catch (SQLiteException e) {
                I i2 = ((Y) this.b).i;
                Y.k(i2);
                i2.g.h("Database error", str, e);
                throw e;
            }
        } catch (Throwable th) {
            if (cursorRawQuery != null) {
                cursorRawQuery.close();
            }
            throw th;
        }
    }

    public final long L0(String str, C2964a1 c2964a1, String str2, Map map, K0 k0, Long l2) {
        long j2;
        int iDelete;
        S();
        T();
        com.google.android.gms.common.internal.u.h(c2964a1);
        com.google.android.gms.common.internal.u.e(str);
        Y y = (Y) this.b;
        if (!y.g.f0(null, AbstractC3893t.M0)) {
            return -1L;
        }
        S();
        T();
        boolean zD0 = D0();
        com.google.android.gms.common.util.b bVar = y.n;
        I i2 = y.i;
        if (zD0) {
            r1 r1Var = this.c;
            long jA = r1Var.i.g.a();
            bVar.getClass();
            long jElapsedRealtime = SystemClock.elapsedRealtime();
            j2 = -1;
            if (Math.abs(jElapsedRealtime - jA) > ((Long) AbstractC3893t.L.a(null)).longValue()) {
                r1Var.i.g.b(jElapsedRealtime);
                S();
                T();
                if (D0() && (iDelete = O0().delete("upload_queue", w0(), new String[0])) > 0) {
                    Y.k(i2);
                    i2.o.g("Deleted stale MeasurementBatch rows from upload_queue. rowsDeleted", Integer.valueOf(iDelete));
                }
                C3891s c3891s = AbstractC3893t.P0;
                C3864e c3864e = y.g;
                if (c3864e.f0(null, c3891s)) {
                    com.google.android.gms.common.internal.u.e(str);
                    S();
                    T();
                    try {
                        int iY = c3864e.Y(str, AbstractC3893t.A);
                        if (iY > 0) {
                            O0().delete("upload_queue", "rowid in (SELECT rowid FROM upload_queue WHERE app_id=? ORDER BY rowid DESC LIMIT -1 OFFSET ?)", new String[]{str, String.valueOf(iY)});
                        }
                    } catch (SQLiteException e) {
                        Y.k(i2);
                        i2.g.h("Error deleting over the limit queued batches. appId", I.a0(str), e);
                    }
                }
            }
        } else {
            j2 = -1;
        }
        ArrayList arrayList = new ArrayList();
        for (Map.Entry entry : map.entrySet()) {
            arrayList.add(((String) entry.getKey()) + SimpleComparison.EQUAL_TO_OPERATION + ((String) entry.getValue()));
        }
        byte[] bArrC = c2964a1.c();
        ContentValues contentValues = new ContentValues();
        contentValues.put("app_id", str);
        contentValues.put("measurement_batch", bArrC);
        contentValues.put("upload_uri", str2);
        StringBuilder sb = new StringBuilder();
        Iterator it2 = arrayList.iterator();
        if (it2.hasNext()) {
            while (true) {
                sb.append((CharSequence) it2.next());
                if (!it2.hasNext()) {
                    break;
                }
                sb.append((CharSequence) "\r\n");
            }
        }
        contentValues.put("upload_headers", sb.toString());
        contentValues.put("upload_type", Integer.valueOf(k0.a));
        bVar.getClass();
        contentValues.put("creation_timestamp", Long.valueOf(System.currentTimeMillis()));
        contentValues.put("retry_count", (Integer) 0);
        if (l2 != null) {
            contentValues.put("associated_row_id", l2);
        }
        try {
            long jInsert = O0().insert("upload_queue", null, contentValues);
            if (jInsert != j2) {
                return jInsert;
            }
            Y.k(i2);
            i2.g.g("Failed to insert MeasurementBatch (got -1) to upload_queue. appId", str);
            return j2;
        } catch (SQLiteException e2) {
            Y.k(i2);
            i2.g.h("Error storing MeasurementBatch to upload_queue. appId", str, e2);
            return j2;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0087 A[Catch: all -> 0x0060, SQLiteException -> 0x0098, TryCatch #0 {SQLiteException -> 0x0098, blocks: (B:15:0x0066, B:17:0x0087, B:20:0x009a), top: B:30:0x0066 }] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x009a A[Catch: all -> 0x0060, SQLiteException -> 0x0098, TRY_LEAVE, TryCatch #0 {SQLiteException -> 0x0098, blocks: (B:15:0x0066, B:17:0x0087, B:20:0x009a), top: B:30:0x0066 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long M0(java.lang.String r14) {
        /*
            r13 = this;
            java.lang.Object r0 = r13.b
            r1 = r0
            com.google.android.gms.measurement.internal.Y r1 = (com.google.android.gms.measurement.internal.Y) r1
            com.google.android.gms.common.internal.u.e(r14)
            java.lang.String r2 = "first_open_count"
            com.google.android.gms.common.internal.u.e(r2)
            r13.S()
            r13.T()
            android.database.sqlite.SQLiteDatabase r3 = r13.O0()
            r3.beginTransaction()
            r4 = 0
            java.lang.String r0 = "select first_open_count from app2 where app_id=?"
            java.lang.String[] r6 = new java.lang.String[]{r14}     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            r7 = -1
            long r9 = r13.K0(r0, r6, r7)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            int r0 = (r9 > r7 ? 1 : (r9 == r7 ? 0 : -1))
            java.lang.String r6 = "app2"
            java.lang.String r11 = "app_id"
            if (r0 != 0) goto L66
            android.content.ContentValues r0 = new android.content.ContentValues     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            r0.<init>()     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            r0.put(r11, r14)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            r9 = 0
            java.lang.Integer r9 = java.lang.Integer.valueOf(r9)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            r0.put(r2, r9)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            java.lang.String r10 = "previous_install_count"
            r0.put(r10, r9)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            r9 = 0
            r10 = 5
            long r9 = r3.insertWithOnConflict(r6, r9, r0, r10)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            int r0 = (r9 > r7 ? 1 : (r9 == r7 ? 0 : -1))
            if (r0 != 0) goto L65
            com.google.android.gms.measurement.internal.I r0 = r1.i     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            com.google.android.gms.measurement.internal.Y.k(r0)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            com.google.android.gms.internal.ads.Ka r0 = r0.g     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            java.lang.String r6 = "Failed to insert column (got -1). appId"
            com.google.android.gms.measurement.internal.H r9 = com.google.android.gms.measurement.internal.I.a0(r14)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            r0.h(r6, r9, r2)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L63
            goto Lb1
        L60:
            r0 = move-exception
            r14 = r0
            goto Lb5
        L63:
            r0 = move-exception
            goto La0
        L65:
            r9 = r4
        L66:
            android.content.ContentValues r0 = new android.content.ContentValues     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            r0.<init>()     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            r0.put(r11, r14)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            r11 = 1
            long r11 = r11 + r9
            java.lang.Long r11 = java.lang.Long.valueOf(r11)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            r0.put(r2, r11)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            java.lang.String r11 = "app_id = ?"
            java.lang.String[] r12 = new java.lang.String[]{r14}     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            int r0 = r3.update(r6, r0, r11, r12)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            long r11 = (long) r0     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            int r0 = (r11 > r4 ? 1 : (r11 == r4 ? 0 : -1))
            if (r0 != 0) goto L9a
            com.google.android.gms.measurement.internal.I r0 = r1.i     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            com.google.android.gms.measurement.internal.Y.k(r0)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            com.google.android.gms.internal.ads.Ka r0 = r0.g     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            java.lang.String r4 = "Failed to update column (got 0). appId"
            com.google.android.gms.measurement.internal.H r5 = com.google.android.gms.measurement.internal.I.a0(r14)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            r0.h(r4, r5, r2)     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            goto Lb1
        L98:
            r0 = move-exception
            goto L9f
        L9a:
            r3.setTransactionSuccessful()     // Catch: java.lang.Throwable -> L60 android.database.sqlite.SQLiteException -> L98
            r7 = r9
            goto Lb1
        L9f:
            r4 = r9
        La0:
            com.google.android.gms.measurement.internal.I r1 = r1.i     // Catch: java.lang.Throwable -> L60
            com.google.android.gms.measurement.internal.Y.k(r1)     // Catch: java.lang.Throwable -> L60
            com.google.android.gms.internal.ads.Ka r1 = r1.g     // Catch: java.lang.Throwable -> L60
            java.lang.String r6 = "Error inserting column. appId"
            com.google.android.gms.measurement.internal.H r14 = com.google.android.gms.measurement.internal.I.a0(r14)     // Catch: java.lang.Throwable -> L60
            r1.i(r6, r14, r2, r0)     // Catch: java.lang.Throwable -> L60
            r7 = r4
        Lb1:
            r3.endTransaction()
            return r7
        Lb5:
            r3.endTransaction()
            throw r14
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.M0(java.lang.String):long");
    }

    public final long N0(String str) {
        com.google.android.gms.common.internal.u.e(str);
        return K0("select count(1) from events where app_id=? and name not like '!_%' escape '!'", new String[]{str}, 0L);
    }

    public final SQLiteDatabase O0() {
        S();
        try {
            return this.e.getWritableDatabase();
        } catch (SQLiteException e) {
            I i2 = ((Y) this.b).i;
            Y.k(i2);
            i2.j.g("Error opening database", e);
            throw e;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:125:0x03fa  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x0400  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.measurement.internal.F P0(java.lang.String r53) {
        /*
            Method dump skipped, instructions count: 1028
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.P0(java.lang.String):com.google.android.gms.measurement.internal.F");
    }

    /* JADX WARN: Not initialized variable reg: 10, insn: 0x00f6: MOVE (r9 I:??[OBJECT, ARRAY]) = (r10 I:??[OBJECT, ARRAY]), block:B:29:0x00f6 */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0116  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x011c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.measurement.internal.zzai Q0(java.lang.String r27, java.lang.String r28) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 288
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.Q0(java.lang.String, java.lang.String):com.google.android.gms.measurement.internal.zzai");
    }

    /* JADX WARN: Not initialized variable reg: 3, insn: 0x006b: MOVE (r2 I:??[OBJECT, ARRAY]) = (r3 I:??[OBJECT, ARRAY]), block:B:19:0x006b */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:35:? A[SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r0v9, types: [byte[], java.io.Serializable] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.quizlet.data.repository.user.a R0(java.lang.String r12) throws java.lang.Throwable {
        /*
            r11 = this;
            java.lang.Object r0 = r11.b
            r1 = r0
            com.google.android.gms.measurement.internal.Y r1 = (com.google.android.gms.measurement.internal.Y) r1
            com.google.android.gms.common.internal.u.e(r12)
            r11.S()
            r11.T()
            r2 = 0
            android.database.sqlite.SQLiteDatabase r3 = r11.O0()     // Catch: java.lang.Throwable -> L6d android.database.sqlite.SQLiteException -> L70
            java.lang.String r4 = "apps"
            java.lang.String r0 = "remote_config"
            java.lang.String r5 = "config_last_modified_time"
            java.lang.String r6 = "e_tag"
            java.lang.String[] r5 = new java.lang.String[]{r0, r5, r6}     // Catch: java.lang.Throwable -> L6d android.database.sqlite.SQLiteException -> L70
            java.lang.String r6 = "app_id=?"
            java.lang.String[] r7 = new java.lang.String[]{r12}     // Catch: java.lang.Throwable -> L6d android.database.sqlite.SQLiteException -> L70
            r10 = 0
            r8 = 0
            r9 = 0
            android.database.Cursor r3 = r3.query(r4, r5, r6, r7, r8, r9, r10)     // Catch: java.lang.Throwable -> L6d android.database.sqlite.SQLiteException -> L70
            boolean r0 = r3.moveToFirst()     // Catch: java.lang.Throwable -> L59 android.database.sqlite.SQLiteException -> L5c
            if (r0 != 0) goto L33
            goto L82
        L33:
            r0 = 0
            byte[] r0 = r3.getBlob(r0)     // Catch: java.lang.Throwable -> L59 android.database.sqlite.SQLiteException -> L5c
            r4 = 1
            java.lang.String r4 = r3.getString(r4)     // Catch: java.lang.Throwable -> L59 android.database.sqlite.SQLiteException -> L5c
            r5 = 2
            java.lang.String r5 = r3.getString(r5)     // Catch: java.lang.Throwable -> L59 android.database.sqlite.SQLiteException -> L5c
            boolean r6 = r3.moveToNext()     // Catch: java.lang.Throwable -> L59 android.database.sqlite.SQLiteException -> L5c
            if (r6 == 0) goto L5e
            com.google.android.gms.measurement.internal.I r6 = r1.i     // Catch: java.lang.Throwable -> L59 android.database.sqlite.SQLiteException -> L5c
            com.google.android.gms.measurement.internal.Y.k(r6)     // Catch: java.lang.Throwable -> L59 android.database.sqlite.SQLiteException -> L5c
            com.google.android.gms.internal.ads.Ka r6 = r6.g     // Catch: java.lang.Throwable -> L59 android.database.sqlite.SQLiteException -> L5c
            java.lang.String r7 = "Got multiple records for app config, expected one. appId"
            com.google.android.gms.measurement.internal.H r8 = com.google.android.gms.measurement.internal.I.a0(r12)     // Catch: java.lang.Throwable -> L59 android.database.sqlite.SQLiteException -> L5c
            r6.g(r7, r8)     // Catch: java.lang.Throwable -> L59 android.database.sqlite.SQLiteException -> L5c
            goto L5e
        L59:
            r0 = move-exception
            r12 = r0
            goto L6b
        L5c:
            r0 = move-exception
            goto L72
        L5e:
            if (r0 != 0) goto L61
            goto L82
        L61:
            com.quizlet.data.repository.user.a r6 = new com.quizlet.data.repository.user.a     // Catch: java.lang.Throwable -> L59 android.database.sqlite.SQLiteException -> L5c
            r7 = 7
            r6.<init>(r0, r4, r5, r7)     // Catch: java.lang.Throwable -> L59 android.database.sqlite.SQLiteException -> L5c
            r3.close()
            return r6
        L6b:
            r2 = r3
            goto L88
        L6d:
            r0 = move-exception
            r12 = r0
            goto L88
        L70:
            r0 = move-exception
            r3 = r2
        L72:
            com.google.android.gms.measurement.internal.I r1 = r1.i     // Catch: java.lang.Throwable -> L59
            com.google.android.gms.measurement.internal.Y.k(r1)     // Catch: java.lang.Throwable -> L59
            com.google.android.gms.internal.ads.Ka r1 = r1.g     // Catch: java.lang.Throwable -> L59
            java.lang.String r4 = "Error querying remote config. appId"
            com.google.android.gms.measurement.internal.H r12 = com.google.android.gms.measurement.internal.I.a0(r12)     // Catch: java.lang.Throwable -> L59
            r1.h(r4, r12, r0)     // Catch: java.lang.Throwable -> L59
        L82:
            if (r3 == 0) goto L87
            r3.close()
        L87:
            return r2
        L88:
            if (r2 == 0) goto L8d
            r2.close()
        L8d:
            throw r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.R0(java.lang.String):com.quizlet.data.repository.user.a");
    }

    public final C3868g S0(long j2, String str, boolean z, boolean z2, boolean z3, boolean z4) {
        return T0(j2, str, 1L, false, false, z, false, z2, z3, z4);
    }

    public final C3868g T0(long j2, String str, long j3, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7) {
        Y y = (Y) this.b;
        com.google.android.gms.common.internal.u.e(str);
        S();
        T();
        String[] strArr = {str};
        C3868g c3868g = new C3868g();
        Cursor cursorQuery = null;
        try {
            try {
                SQLiteDatabase sQLiteDatabaseO0 = O0();
                cursorQuery = sQLiteDatabaseO0.query("apps", new String[]{"day", "daily_events_count", "daily_public_events_count", "daily_conversions_count", "daily_error_events_count", "daily_realtime_events_count", "daily_realtime_dcu_count", "daily_registered_triggers_count"}, "app_id=?", new String[]{str}, null, null, null);
                if (cursorQuery.moveToFirst()) {
                    if (cursorQuery.getLong(0) == j2) {
                        c3868g.b = cursorQuery.getLong(1);
                        c3868g.a = cursorQuery.getLong(2);
                        c3868g.c = cursorQuery.getLong(3);
                        c3868g.d = cursorQuery.getLong(4);
                        c3868g.e = cursorQuery.getLong(5);
                        c3868g.f = cursorQuery.getLong(6);
                        c3868g.g = cursorQuery.getLong(7);
                    }
                    if (z) {
                        c3868g.b += j3;
                    }
                    if (z2) {
                        c3868g.a += j3;
                    }
                    if (z3) {
                        c3868g.c += j3;
                    }
                    if (z4) {
                        c3868g.d += j3;
                    }
                    if (z5) {
                        c3868g.e += j3;
                    }
                    if (z6) {
                        c3868g.f += j3;
                    }
                    if (z7) {
                        c3868g.g += j3;
                    }
                    ContentValues contentValues = new ContentValues();
                    contentValues.put("day", Long.valueOf(j2));
                    contentValues.put("daily_public_events_count", Long.valueOf(c3868g.a));
                    contentValues.put("daily_events_count", Long.valueOf(c3868g.b));
                    contentValues.put("daily_conversions_count", Long.valueOf(c3868g.c));
                    contentValues.put("daily_error_events_count", Long.valueOf(c3868g.d));
                    contentValues.put("daily_realtime_events_count", Long.valueOf(c3868g.e));
                    contentValues.put("daily_realtime_dcu_count", Long.valueOf(c3868g.f));
                    contentValues.put("daily_registered_triggers_count", Long.valueOf(c3868g.g));
                    sQLiteDatabaseO0.update("apps", contentValues, "app_id=?", strArr);
                } else {
                    I i2 = y.i;
                    Y.k(i2);
                    i2.j.g("Not updating daily counts, app is not known. appId", I.a0(str));
                }
            } catch (SQLiteException e) {
                I i3 = y.i;
                Y.k(i3);
                i3.g.h("Error updating daily counts. appId", I.a0(str), e);
            }
            if (cursorQuery != null) {
                cursorQuery.close();
            }
            return c3868g;
        } catch (Throwable th) {
            if (0 != 0) {
                cursorQuery.close();
            }
            throw th;
        }
    }

    public final C3882n U0(String str, com.google.android.gms.internal.measurement.U0 u0, String str2) {
        C3882n c3882nU0 = u0("events", str, u0.t());
        if (c3882nU0 != null) {
            long j2 = c3882nU0.e + 1;
            long j3 = c3882nU0.d + 1;
            return new C3882n(c3882nU0.a, c3882nU0.b, c3882nU0.c + 1, j3, j2, c3882nU0.f, c3882nU0.g, c3882nU0.h, c3882nU0.i, c3882nU0.j, c3882nU0.k);
        }
        Y y = (Y) this.b;
        I i2 = y.i;
        Y.k(i2);
        i2.j.h("Event aggregate wasn't created during raw event logging. appId, event", I.a0(str), y.m.d(str2));
        return new C3882n(str, u0.t(), 1L, 1L, 1L, u0.q(), 0L, null, null, null, null);
    }

    @Override // com.google.android.gms.measurement.internal.m1
    public final void V() {
    }

    public final C3881m0 V0(String str) {
        com.google.android.gms.common.internal.u.h(str);
        S();
        T();
        return C3881m0.e(100, x0("select storage_consent_at_bundling from consent_settings where app_id=? limit 1;", new String[]{str}));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0039  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x003f  */
    /* JADX WARN: Type inference failed for: r1v0 */
    /* JADX WARN: Type inference failed for: r1v1, types: [android.database.Cursor] */
    /* JADX WARN: Type inference failed for: r1v3 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String W() throws java.lang.Throwable {
        /*
            r6 = this;
            android.database.sqlite.SQLiteDatabase r0 = r6.O0()
            r1 = 0
            java.lang.String r2 = "select app_id from queue order by has_realtime desc, rowid asc limit 1;"
            android.database.Cursor r0 = r0.rawQuery(r2, r1)     // Catch: java.lang.Throwable -> L22 android.database.sqlite.SQLiteException -> L24
            boolean r2 = r0.moveToFirst()     // Catch: java.lang.Throwable -> L1a android.database.sqlite.SQLiteException -> L1c
            if (r2 == 0) goto L37
            r2 = 0
            java.lang.String r1 = r0.getString(r2)     // Catch: java.lang.Throwable -> L1a android.database.sqlite.SQLiteException -> L1c
            r0.close()
            return r1
        L1a:
            r1 = move-exception
            goto L1e
        L1c:
            r2 = move-exception
            goto L27
        L1e:
            r5 = r1
            r1 = r0
            r0 = r5
            goto L3d
        L22:
            r0 = move-exception
            goto L3d
        L24:
            r0 = move-exception
            r2 = r0
            r0 = r1
        L27:
            java.lang.Object r3 = r6.b     // Catch: java.lang.Throwable -> L1a
            com.google.android.gms.measurement.internal.Y r3 = (com.google.android.gms.measurement.internal.Y) r3     // Catch: java.lang.Throwable -> L1a
            com.google.android.gms.measurement.internal.I r3 = r3.i     // Catch: java.lang.Throwable -> L1a
            com.google.android.gms.measurement.internal.Y.k(r3)     // Catch: java.lang.Throwable -> L1a
            com.google.android.gms.internal.ads.Ka r3 = r3.g     // Catch: java.lang.Throwable -> L1a
            java.lang.String r4 = "Database error getting next bundle app id"
            r3.g(r4, r2)     // Catch: java.lang.Throwable -> L1a
        L37:
            if (r0 == 0) goto L3c
            r0.close()
        L3c:
            return r1
        L3d:
            if (r1 == 0) goto L42
            r1.close()
        L42:
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.W():java.lang.String");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:24:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0061 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0064  */
    /* JADX WARN: Type inference failed for: r3v1, types: [android.database.sqlite.SQLiteDatabase] */
    /* JADX WARN: Type inference failed for: r5v1, types: [java.lang.String[]] */
    /* JADX WARN: Type inference failed for: r5v4 */
    /* JADX WARN: Type inference failed for: r5v5 */
    /* JADX WARN: Type inference failed for: r5v6 */
    /* JADX WARN: Type inference failed for: r5v8, types: [android.database.Cursor] */
    /* JADX WARN: Type inference failed for: r5v9, types: [android.database.Cursor] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.measurement.internal.C3881m0 W0(java.lang.String r5) {
        /*
            r4 = this;
            java.lang.Object r0 = r4.b
            com.google.android.gms.measurement.internal.Y r0 = (com.google.android.gms.measurement.internal.Y) r0
            com.google.android.gms.common.internal.u.h(r5)
            r4.S()
            r4.T()
            java.lang.String[] r5 = new java.lang.String[]{r5}
            java.lang.String r1 = "select consent_state, consent_source from consent_settings where app_id=? limit 1;"
            r2 = 0
            android.database.sqlite.SQLiteDatabase r3 = r4.O0()     // Catch: java.lang.Throwable -> L47 android.database.sqlite.SQLiteException -> L4a
            android.database.Cursor r5 = r3.rawQuery(r1, r5)     // Catch: java.lang.Throwable -> L47 android.database.sqlite.SQLiteException -> L4a
            boolean r1 = r5.moveToFirst()     // Catch: java.lang.Throwable -> L32 android.database.sqlite.SQLiteException -> L34
            if (r1 != 0) goto L36
            com.google.android.gms.measurement.internal.I r1 = r0.i     // Catch: java.lang.Throwable -> L32 android.database.sqlite.SQLiteException -> L34
            com.google.android.gms.measurement.internal.Y.k(r1)     // Catch: java.lang.Throwable -> L32 android.database.sqlite.SQLiteException -> L34
            com.google.android.gms.internal.ads.Ka r1 = r1.o     // Catch: java.lang.Throwable -> L32 android.database.sqlite.SQLiteException -> L34
            java.lang.String r3 = "No data found"
            r1.f(r3)     // Catch: java.lang.Throwable -> L32 android.database.sqlite.SQLiteException -> L34
        L2e:
            r5.close()
            goto L5c
        L32:
            r0 = move-exception
            goto L45
        L34:
            r1 = move-exception
            goto L4d
        L36:
            r1 = 0
            java.lang.String r1 = r5.getString(r1)     // Catch: java.lang.Throwable -> L32 android.database.sqlite.SQLiteException -> L34
            r3 = 1
            int r3 = r5.getInt(r3)     // Catch: java.lang.Throwable -> L32 android.database.sqlite.SQLiteException -> L34
            com.google.android.gms.measurement.internal.m0 r2 = com.google.android.gms.measurement.internal.C3881m0.e(r3, r1)     // Catch: java.lang.Throwable -> L32 android.database.sqlite.SQLiteException -> L34
            goto L2e
        L45:
            r2 = r5
            goto L62
        L47:
            r5 = move-exception
            r0 = r5
            goto L62
        L4a:
            r5 = move-exception
            r1 = r5
            r5 = r2
        L4d:
            com.google.android.gms.measurement.internal.I r0 = r0.i     // Catch: java.lang.Throwable -> L32
            com.google.android.gms.measurement.internal.Y.k(r0)     // Catch: java.lang.Throwable -> L32
            com.google.android.gms.internal.ads.Ka r0 = r0.g     // Catch: java.lang.Throwable -> L32
            java.lang.String r3 = "Error querying database."
            r0.g(r3, r1)     // Catch: java.lang.Throwable -> L32
            if (r5 == 0) goto L5c
            goto L2e
        L5c:
            if (r2 != 0) goto L61
            com.google.android.gms.measurement.internal.m0 r5 = com.google.android.gms.measurement.internal.C3881m0.c
            return r5
        L61:
            return r2
        L62:
            if (r2 == 0) goto L67
            r2.close()
        L67:
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.W0(java.lang.String):com.google.android.gms.measurement.internal.m0");
    }

    public final List X(String str, String str2, String str3) {
        com.google.android.gms.common.internal.u.e(str);
        S();
        T();
        ArrayList arrayList = new ArrayList(3);
        arrayList.add(str);
        StringBuilder sb = new StringBuilder("app_id=?");
        if (!TextUtils.isEmpty(str2)) {
            arrayList.add(str2);
            sb.append(" and origin=?");
        }
        if (!TextUtils.isEmpty(str3)) {
            arrayList.add(String.valueOf(str3).concat("*"));
            sb.append(" and name glob ?");
        }
        return Y(sb.toString(), (String[]) arrayList.toArray(new String[arrayList.size()]));
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x00f9  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0101  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.measurement.internal.t1 X0(java.lang.String r27) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 262
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.X0(java.lang.String):com.google.android.gms.measurement.internal.t1");
    }

    /* JADX WARN: Code restructure failed: missing block: B:7:0x0056, code lost:
    
        r3 = r2.i;
        com.google.android.gms.measurement.internal.Y.k(r3);
        r3.g.g("Read more than the max allowed conditional properties, ignoring extra", 1000);
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r0v3, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r0v5, types: [java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.List Y(java.lang.String r29, java.lang.String[] r30) {
        /*
            Method dump skipped, instructions count: 278
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.Y(java.lang.String, java.lang.String[]):java.util.List");
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x009d  */
    /* JADX WARN: Removed duplicated region for block: B:43:? A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.measurement.internal.v1 Y0(java.lang.String r12, java.lang.String r13) {
        /*
            r11 = this;
            java.lang.Object r0 = r11.b
            r1 = r0
            com.google.android.gms.measurement.internal.Y r1 = (com.google.android.gms.measurement.internal.Y) r1
            com.google.android.gms.common.internal.u.e(r12)
            com.google.android.gms.common.internal.u.e(r13)
            r11.S()
            r11.T()
            r2 = 0
            android.database.sqlite.SQLiteDatabase r3 = r11.O0()     // Catch: java.lang.Throwable -> L77 android.database.sqlite.SQLiteException -> L7a
            java.lang.String r4 = "user_attributes"
            java.lang.String r0 = "set_timestamp"
            java.lang.String r5 = "value"
            java.lang.String r6 = "origin"
            java.lang.String[] r5 = new java.lang.String[]{r0, r5, r6}     // Catch: java.lang.Throwable -> L77 android.database.sqlite.SQLiteException -> L7a
            java.lang.String r6 = "app_id=? and name=?"
            java.lang.String[] r7 = new java.lang.String[]{r12, r13}     // Catch: java.lang.Throwable -> L77 android.database.sqlite.SQLiteException -> L7a
            r10 = 0
            r8 = 0
            r9 = 0
            android.database.Cursor r3 = r3.query(r4, r5, r6, r7, r8, r9, r10)     // Catch: java.lang.Throwable -> L77 android.database.sqlite.SQLiteException -> L7a
            boolean r0 = r3.moveToFirst()     // Catch: java.lang.Throwable -> L67 android.database.sqlite.SQLiteException -> L71
            if (r0 != 0) goto L37
            goto L95
        L37:
            r0 = 0
            long r8 = r3.getLong(r0)     // Catch: java.lang.Throwable -> L67 android.database.sqlite.SQLiteException -> L71
            r0 = 1
            java.lang.Object r10 = r11.Z0(r3, r0)     // Catch: java.lang.Throwable -> L67 android.database.sqlite.SQLiteException -> L71
            if (r10 != 0) goto L44
            goto L95
        L44:
            r0 = 2
            java.lang.String r6 = r3.getString(r0)     // Catch: java.lang.Throwable -> L67 android.database.sqlite.SQLiteException -> L71
            com.google.android.gms.measurement.internal.v1 r4 = new com.google.android.gms.measurement.internal.v1     // Catch: java.lang.Throwable -> L67 android.database.sqlite.SQLiteException -> L71
            r5 = r12
            r7 = r13
            r4.<init>(r5, r6, r7, r8, r10)     // Catch: java.lang.Throwable -> L67 android.database.sqlite.SQLiteException -> L6a
            boolean r12 = r3.moveToNext()     // Catch: java.lang.Throwable -> L67 android.database.sqlite.SQLiteException -> L6a
            if (r12 == 0) goto L6d
            com.google.android.gms.measurement.internal.I r12 = r1.i     // Catch: java.lang.Throwable -> L67 android.database.sqlite.SQLiteException -> L6a
            com.google.android.gms.measurement.internal.Y.k(r12)     // Catch: java.lang.Throwable -> L67 android.database.sqlite.SQLiteException -> L6a
            com.google.android.gms.internal.ads.Ka r12 = r12.g     // Catch: java.lang.Throwable -> L67 android.database.sqlite.SQLiteException -> L6a
            java.lang.String r13 = "Got multiple records for user property, expected one. appId"
            com.google.android.gms.measurement.internal.H r0 = com.google.android.gms.measurement.internal.I.a0(r5)     // Catch: java.lang.Throwable -> L67 android.database.sqlite.SQLiteException -> L6a
            r12.g(r13, r0)     // Catch: java.lang.Throwable -> L67 android.database.sqlite.SQLiteException -> L6a
            goto L6d
        L67:
            r0 = move-exception
            r12 = r0
            goto L75
        L6a:
            r0 = move-exception
        L6b:
            r12 = r0
            goto L7f
        L6d:
            r3.close()
            return r4
        L71:
            r0 = move-exception
            r5 = r12
            r7 = r13
            goto L6b
        L75:
            r2 = r3
            goto L9b
        L77:
            r0 = move-exception
            r12 = r0
            goto L9b
        L7a:
            r0 = move-exception
            r5 = r12
            r7 = r13
            r12 = r0
            r3 = r2
        L7f:
            com.google.android.gms.measurement.internal.I r13 = r1.i     // Catch: java.lang.Throwable -> L67
            com.google.android.gms.measurement.internal.Y.k(r13)     // Catch: java.lang.Throwable -> L67
            com.google.android.gms.internal.ads.Ka r13 = r13.g     // Catch: java.lang.Throwable -> L67
            java.lang.String r0 = "Error querying user property. appId"
            com.google.android.gms.measurement.internal.H r4 = com.google.android.gms.measurement.internal.I.a0(r5)     // Catch: java.lang.Throwable -> L67
            com.google.android.gms.measurement.internal.D r1 = r1.m     // Catch: java.lang.Throwable -> L67
            java.lang.String r1 = r1.f(r7)     // Catch: java.lang.Throwable -> L67
            r13.i(r0, r4, r1, r12)     // Catch: java.lang.Throwable -> L67
        L95:
            if (r3 == 0) goto L9a
            r3.close()
        L9a:
            return r2
        L9b:
            if (r2 == 0) goto La0
            r2.close()
        La0:
            throw r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.Y0(java.lang.String, java.lang.String):com.google.android.gms.measurement.internal.v1");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00d8  */
    /* JADX WARN: Type inference failed for: r0v10, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r0v5, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r0v6, types: [java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.List Z(java.lang.String r26, com.google.android.gms.measurement.internal.zzpc r27, int r28) {
        /*
            Method dump skipped, instructions count: 226
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.Z(java.lang.String, com.google.android.gms.measurement.internal.zzpc, int):java.util.List");
    }

    public final Object Z0(Cursor cursor, int i2) {
        int type = cursor.getType(i2);
        Y y = (Y) this.b;
        if (type == 0) {
            I i3 = y.i;
            Y.k(i3);
            i3.g.f("Loaded invalid null value from database");
            return null;
        }
        if (type == 1) {
            return Long.valueOf(cursor.getLong(i2));
        }
        if (type == 2) {
            return Double.valueOf(cursor.getDouble(i2));
        }
        if (type == 3) {
            return cursor.getString(i2);
        }
        if (type == 4) {
            I i4 = y.i;
            Y.k(i4);
            i4.g.f("Loaded invalid blob type value, ignoring it");
            return null;
        }
        I i5 = y.i;
        Y.k(i5);
        i5.g.g("Loaded invalid unknown value type, ignoring it", Integer.valueOf(type));
        return null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:30:0x009e  */
    /* JADX WARN: Type inference failed for: r0v1, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r0v4, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r0v6, types: [java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.List a0(java.lang.String r13) {
        /*
            r12 = this;
            java.lang.Object r0 = r12.b
            r1 = r0
            com.google.android.gms.measurement.internal.Y r1 = (com.google.android.gms.measurement.internal.Y) r1
            com.google.android.gms.common.internal.u.e(r13)
            r12.S()
            r12.T()
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>()
            java.lang.String r10 = "1000"
            r11 = 0
            android.database.sqlite.SQLiteDatabase r2 = r12.O0()     // Catch: java.lang.Throwable -> L70 android.database.sqlite.SQLiteException -> L87
            java.lang.String r3 = "user_attributes"
            java.lang.String r4 = "name"
            java.lang.String r5 = "origin"
            java.lang.String r6 = "set_timestamp"
            java.lang.String r7 = "value"
            java.lang.String[] r4 = new java.lang.String[]{r4, r5, r6, r7}     // Catch: java.lang.Throwable -> L70 android.database.sqlite.SQLiteException -> L87
            java.lang.String r5 = "app_id=?"
            java.lang.String[] r6 = new java.lang.String[]{r13}     // Catch: java.lang.Throwable -> L70 android.database.sqlite.SQLiteException -> L87
            java.lang.String r9 = "rowid"
            r1.getClass()     // Catch: java.lang.Throwable -> L70 android.database.sqlite.SQLiteException -> L87
            r7 = 0
            r8 = 0
            android.database.Cursor r11 = r2.query(r3, r4, r5, r6, r7, r8, r9, r10)     // Catch: java.lang.Throwable -> L70 android.database.sqlite.SQLiteException -> L87
            boolean r2 = r11.moveToFirst()     // Catch: android.database.sqlite.SQLiteException -> L4f java.lang.Throwable -> L70
            if (r2 == 0) goto L9c
        L3f:
            r2 = 0
            java.lang.String r6 = r11.getString(r2)     // Catch: android.database.sqlite.SQLiteException -> L4f java.lang.Throwable -> L70
            r2 = 1
            java.lang.String r2 = r11.getString(r2)     // Catch: android.database.sqlite.SQLiteException -> L4f java.lang.Throwable -> L70
            if (r2 != 0) goto L4d
            java.lang.String r2 = ""
        L4d:
            r5 = r2
            goto L52
        L4f:
            r0 = move-exception
            r4 = r13
            goto L8a
        L52:
            r2 = 2
            long r7 = r11.getLong(r2)     // Catch: android.database.sqlite.SQLiteException -> L4f java.lang.Throwable -> L70
            r2 = 3
            java.lang.Object r9 = r12.Z0(r11, r2)     // Catch: android.database.sqlite.SQLiteException -> L4f java.lang.Throwable -> L70
            if (r9 != 0) goto L73
            com.google.android.gms.measurement.internal.I r2 = r1.i     // Catch: android.database.sqlite.SQLiteException -> L4f java.lang.Throwable -> L70
            com.google.android.gms.measurement.internal.Y.k(r2)     // Catch: android.database.sqlite.SQLiteException -> L4f java.lang.Throwable -> L70
            com.google.android.gms.internal.ads.Ka r2 = r2.g     // Catch: android.database.sqlite.SQLiteException -> L4f java.lang.Throwable -> L70
            java.lang.String r3 = "Read invalid user property value, ignoring it. appId"
            com.google.android.gms.measurement.internal.H r4 = com.google.android.gms.measurement.internal.I.a0(r13)     // Catch: android.database.sqlite.SQLiteException -> L4f java.lang.Throwable -> L70
            r2.g(r3, r4)     // Catch: android.database.sqlite.SQLiteException -> L4f java.lang.Throwable -> L70
            r4 = r13
            goto L7c
        L70:
            r0 = move-exception
            r13 = r0
            goto La2
        L73:
            com.google.android.gms.measurement.internal.v1 r3 = new com.google.android.gms.measurement.internal.v1     // Catch: android.database.sqlite.SQLiteException -> L4f java.lang.Throwable -> L70
            r4 = r13
            r3.<init>(r4, r5, r6, r7, r9)     // Catch: java.lang.Throwable -> L70 android.database.sqlite.SQLiteException -> L85
            r0.add(r3)     // Catch: java.lang.Throwable -> L70 android.database.sqlite.SQLiteException -> L85
        L7c:
            boolean r13 = r11.moveToNext()     // Catch: java.lang.Throwable -> L70 android.database.sqlite.SQLiteException -> L85
            if (r13 != 0) goto L83
            goto L9c
        L83:
            r13 = r4
            goto L3f
        L85:
            r0 = move-exception
            goto L8a
        L87:
            r0 = move-exception
            r4 = r13
            r13 = r0
        L8a:
            com.google.android.gms.measurement.internal.I r13 = r1.i     // Catch: java.lang.Throwable -> L70
            com.google.android.gms.measurement.internal.Y.k(r13)     // Catch: java.lang.Throwable -> L70
            com.google.android.gms.internal.ads.Ka r13 = r13.g     // Catch: java.lang.Throwable -> L70
            java.lang.String r1 = "Error querying user properties. appId"
            com.google.android.gms.measurement.internal.H r2 = com.google.android.gms.measurement.internal.I.a0(r4)     // Catch: java.lang.Throwable -> L70
            r13.h(r1, r2, r0)     // Catch: java.lang.Throwable -> L70
            java.util.List r0 = java.util.Collections.EMPTY_LIST     // Catch: java.lang.Throwable -> L70
        L9c:
            if (r11 == 0) goto La1
            r11.close()
        La1:
            return r0
        La2:
            if (r11 == 0) goto La7
            r11.close()
        La7:
            throw r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.a0(java.lang.String):java.util.List");
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x00a6, code lost:
    
        com.google.android.gms.measurement.internal.Y.k(r7);
        r7.g.g("Read more than the max allowed user properties, ignoring excess", 1000);
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0118  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x011e  */
    /* JADX WARN: Type inference failed for: r3v0, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r3v1, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r3v3, types: [java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.List b0(java.lang.String r17, java.lang.String r18, java.lang.String r19) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 290
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.b0(java.lang.String, java.lang.String, java.lang.String):java.util.List");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0117 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00f5  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x013c  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x01cb  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0268 A[Catch: SQLiteException -> 0x0285, TRY_LEAVE, TryCatch #4 {SQLiteException -> 0x0285, blocks: (B:83:0x024d, B:85:0x0268), top: B:102:0x024d }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c0(java.lang.String r28, java.lang.Long r29, java.lang.String r30, android.os.Bundle r31) {
        /*
            Method dump skipped, instructions count: 677
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.c0(java.lang.String, java.lang.Long, java.lang.String, android.os.Bundle):void");
    }

    public final void d0() {
        T();
        O0().beginTransaction();
    }

    public final void e0(String str) {
        C3882n c3882nU0;
        y0("events_snapshot", str);
        Cursor cursorQuery = null;
        try {
            try {
                cursorQuery = O0().query("events", (String[]) Collections.singletonList("name").toArray(new String[0]), "app_id=?", new String[]{str}, null, null, null);
                if (cursorQuery.moveToFirst()) {
                    do {
                        String string = cursorQuery.getString(0);
                        if (string != null && (c3882nU0 = u0("events", str, string)) != null) {
                            z0("events_snapshot", c3882nU0);
                        }
                    } while (cursorQuery.moveToNext());
                }
            } catch (SQLiteException e) {
                I i2 = ((Y) this.b).i;
                Y.k(i2);
                i2.g.h("Error creating snapshot. appId", I.a0(str), e);
            }
            if (cursorQuery != null) {
                cursorQuery.close();
            }
        } finally {
        }
    }

    public final void f0(ArrayList arrayList) {
        com.google.android.gms.common.internal.u.h(arrayList);
        S();
        T();
        StringBuilder sb = new StringBuilder("rowid in (");
        for (int i2 = 0; i2 < arrayList.size(); i2++) {
            if (i2 != 0) {
                sb.append(",");
            }
            sb.append(((Long) arrayList.get(i2)).longValue());
        }
        sb.append(")");
        int iDelete = O0().delete("raw_events", sb.toString(), null);
        if (iDelete != arrayList.size()) {
            I i3 = ((Y) this.b).i;
            Y.k(i3);
            i3.g.h("Deleted fewer rows from raw events table than expected", Integer.valueOf(iDelete), Integer.valueOf(arrayList.size()));
        }
    }

    public final void g0(Long l2) {
        S();
        T();
        Y y = (Y) this.b;
        C3864e c3864e = y.g;
        I i2 = y.i;
        if (c3864e.f0(null, AbstractC3893t.M0)) {
            try {
                if (O0().delete("upload_queue", "rowid=?", new String[]{l2.toString()}) != 1) {
                    Y.k(i2);
                    i2.j.f("Deleted fewer rows from upload_queue than expected");
                }
            } catch (SQLiteException e) {
                Y.k(i2);
                i2.g.g("Failed to delete a MeasurementBatch in a upload_queue table", e);
                throw e;
            }
        }
    }

    public final void h0() {
        T();
        O0().endTransaction();
    }

    public final void i0(ArrayList arrayList) throws SQLException {
        S();
        T();
        com.google.android.gms.common.internal.u.h(arrayList);
        if (arrayList.size() == 0) {
            throw new IllegalArgumentException("Given Integer is zero");
        }
        if (D0()) {
            String strB = android.support.v4.media.session.a.B("(", TextUtils.join(",", arrayList), ")");
            long jJ0 = J0("SELECT COUNT(1) FROM queue WHERE rowid IN " + strB + " AND retry_count =  2147483647 LIMIT 1", null);
            Y y = (Y) this.b;
            if (jJ0 > 0) {
                I i2 = y.i;
                Y.k(i2);
                i2.j.f("The number of upload retries exceeds the limit. Will remain unchanged.");
            }
            try {
                O0().execSQL("UPDATE queue SET retry_count = IFNULL(retry_count, 0) + 1 WHERE rowid IN " + strB + " AND (retry_count IS NULL OR retry_count < 2147483647)");
            } catch (SQLiteException e) {
                I i3 = y.i;
                Y.k(i3);
                i3.g.g("Error incrementing retry count. error", e);
            }
        }
    }

    public final void j0(Long l2) {
        String str;
        S();
        T();
        Y y = (Y) this.b;
        if (y.g.f0(null, AbstractC3893t.M0) && D0()) {
            long jJ0 = J0("SELECT COUNT(1) FROM upload_queue WHERE rowid = " + l2 + " AND retry_count =  2147483647 LIMIT 1", null);
            I i2 = y.i;
            if (jJ0 > 0) {
                Y.k(i2);
                i2.j.f("The number of upload retries exceeds the limit. Will remain unchanged.");
            }
            try {
                SQLiteDatabase sQLiteDatabaseO0 = O0();
                if (y.g.f0(null, AbstractC3893t.P0)) {
                    y.n.getClass();
                    str = " SET retry_count = retry_count + 1, last_upload_timestamp = " + System.currentTimeMillis();
                } else {
                    str = " SET retry_count = retry_count + 1 ";
                }
                sQLiteDatabaseO0.execSQL("UPDATE upload_queue" + str + " WHERE rowid = " + l2 + " AND retry_count < 2147483647");
            } catch (SQLiteException e) {
                Y.k(i2);
                i2.g.g("Error incrementing retry count. error", e);
            }
        }
    }

    public final void k0() {
        S();
        T();
        if (D0()) {
            r1 r1Var = this.c;
            long jA = r1Var.i.f.a();
            Y y = (Y) this.b;
            y.n.getClass();
            long jElapsedRealtime = SystemClock.elapsedRealtime();
            if (Math.abs(jElapsedRealtime - jA) > ((Long) AbstractC3893t.L.a(null)).longValue()) {
                r1Var.i.f.b(jElapsedRealtime);
                S();
                T();
                if (D0()) {
                    SQLiteDatabase sQLiteDatabaseO0 = O0();
                    y.n.getClass();
                    int iDelete = sQLiteDatabaseO0.delete("queue", "abs(bundle_end_timestamp - ?) > cast(? as integer)", new String[]{String.valueOf(System.currentTimeMillis()), String.valueOf(((Long) AbstractC3893t.Q.a(null)).longValue())});
                    if (iDelete > 0) {
                        I i2 = y.i;
                        Y.k(i2);
                        i2.o.g("Deleted stale rows. rowsDeleted", Integer.valueOf(iDelete));
                    }
                }
            }
        }
    }

    public final void l0(String str, String str2) {
        com.google.android.gms.common.internal.u.e(str);
        com.google.android.gms.common.internal.u.e(str2);
        S();
        T();
        try {
            O0().delete("user_attributes", "app_id=? and name=?", new String[]{str, str2});
        } catch (SQLiteException e) {
            Y y = (Y) this.b;
            I i2 = y.i;
            Y.k(i2);
            i2.g.i("Error deleting user property. appId", I.a0(str), y.m.f(str2), e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00cb  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00d7  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0054  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x005b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m0(java.lang.String r20) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 226
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.m0(java.lang.String):void");
    }

    public final void n0() {
        T();
        O0().setTransactionSuccessful();
    }

    public final void o0(F f, boolean z) {
        S();
        T();
        String strC = f.c();
        com.google.android.gms.common.internal.u.h(strC);
        ContentValues contentValues = new ContentValues();
        contentValues.put("app_id", strC);
        EnumC3879l0 enumC3879l0 = EnumC3879l0.ANALYTICS_STORAGE;
        r1 r1Var = this.c;
        if (z) {
            contentValues.put("app_instance_id", (String) null);
        } else if (r1Var.n0(strC).k(enumC3879l0)) {
            contentValues.put("app_instance_id", f.d());
        }
        contentValues.put("gmp_app_id", f.g());
        boolean zK = r1Var.n0(strC).k(EnumC3879l0.AD_STORAGE);
        Y y = f.a;
        if (zK) {
            X x = y.j;
            Y.k(x);
            x.S();
            contentValues.put("resettable_device_id_hash", f.e);
        }
        X x2 = y.j;
        Y.k(x2);
        x2.S();
        contentValues.put("last_bundle_index", Long.valueOf(f.g));
        X x3 = y.j;
        Y.k(x3);
        x3.S();
        contentValues.put("last_bundle_start_timestamp", Long.valueOf(f.h));
        X x4 = y.j;
        Y.k(x4);
        x4.S();
        contentValues.put("last_bundle_end_timestamp", Long.valueOf(f.i));
        contentValues.put("app_version", f.e());
        X x5 = y.j;
        Y.k(x5);
        x5.S();
        contentValues.put("app_store", f.l);
        X x6 = y.j;
        Y.k(x6);
        x6.S();
        contentValues.put("gmp_version", Long.valueOf(f.m));
        X x7 = y.j;
        Y.k(x7);
        x7.S();
        contentValues.put("dev_cert_hash", Long.valueOf(f.n));
        X x8 = y.j;
        Y.k(x8);
        x8.S();
        contentValues.put("measurement_enabled", Boolean.valueOf(f.o));
        X x9 = y.j;
        Y.k(x9);
        x9.S();
        contentValues.put("day", Long.valueOf(f.K));
        X x10 = y.j;
        Y.k(x10);
        x10.S();
        contentValues.put("daily_public_events_count", Long.valueOf(f.L));
        Y.k(x10);
        x10.S();
        contentValues.put("daily_events_count", Long.valueOf(f.M));
        Y.k(x10);
        x10.S();
        contentValues.put("daily_conversions_count", Long.valueOf(f.N));
        X x11 = y.j;
        Y.k(x11);
        x11.S();
        contentValues.put("config_fetched_time", Long.valueOf(f.S));
        X x12 = y.j;
        Y.k(x12);
        x12.S();
        contentValues.put("failed_config_fetch_time", Long.valueOf(f.T));
        contentValues.put("app_version_int", Long.valueOf(f.S()));
        contentValues.put("firebase_instance_id", f.f());
        Y.k(x10);
        x10.S();
        contentValues.put("daily_error_events_count", Long.valueOf(f.O));
        Y.k(x10);
        x10.S();
        contentValues.put("daily_realtime_events_count", Long.valueOf(f.P));
        Y.k(x10);
        x10.S();
        contentValues.put("health_monitor_sample", f.Q);
        contentValues.put("android_id", (Long) 0L);
        X x13 = y.j;
        Y.k(x13);
        x13.S();
        contentValues.put("adid_reporting_enabled", Boolean.valueOf(f.p));
        contentValues.put("admob_app_id", f.a());
        contentValues.put("dynamite_version", Long.valueOf(f.T()));
        if (r1Var.n0(strC).k(enumC3879l0)) {
            X x14 = y.j;
            Y.k(x14);
            x14.S();
            contentValues.put("session_stitching_token", f.u);
        }
        contentValues.put("sgtm_upload_enabled", Boolean.valueOf(f.t()));
        X x15 = y.j;
        Y.k(x15);
        x15.S();
        contentValues.put("target_os_version", Long.valueOf(f.w));
        X x16 = y.j;
        Y.k(x16);
        x16.S();
        contentValues.put("session_stitching_token_hash", Long.valueOf(f.x));
        E3.b();
        Y y2 = (Y) this.b;
        if (y2.g.f0(strC, AbstractC3893t.V0)) {
            X x17 = y.j;
            Y.k(x17);
            x17.S();
            contentValues.put("ad_services_version", Integer.valueOf(f.y));
            X x18 = y.j;
            Y.k(x18);
            x18.S();
            contentValues.put("attribution_eligibility_status", Long.valueOf(f.C));
        }
        X x19 = y.j;
        Y.k(x19);
        x19.S();
        contentValues.put("unmatched_first_open_without_ad_id", Boolean.valueOf(f.z));
        contentValues.put("npa_metadata_value", f.U());
        X x20 = y.j;
        Y.k(x20);
        x20.S();
        contentValues.put("bundle_delivery_index", Long.valueOf(f.G));
        contentValues.put("sgtm_preview_key", f.i());
        Y.k(x10);
        x10.S();
        contentValues.put("dma_consent_state", Integer.valueOf(f.E));
        Y.k(x10);
        x10.S();
        contentValues.put("daily_realtime_dcu_count", Integer.valueOf(f.F));
        contentValues.put("serialized_npa_metadata", f.h());
        C3891s c3891s = AbstractC3893t.P0;
        C3864e c3864e = y2.g;
        if (c3864e.f0(strC, c3891s)) {
            contentValues.put("client_upload_eligibility", Integer.valueOf(f.R()));
        }
        X x21 = y.j;
        Y.k(x21);
        x21.S();
        ArrayList arrayList = f.t;
        I i2 = y2.i;
        if (arrayList != null) {
            if (arrayList.isEmpty()) {
                Y.k(i2);
                i2.j.g("Safelisted events should not be an empty list. appId", strC);
            } else {
                contentValues.put("safelisted_events", TextUtils.join(",", arrayList));
            }
        }
        if (c3864e.f0(null, AbstractC3893t.J0) && !contentValues.containsKey("safelisted_events")) {
            contentValues.put("safelisted_events", (String) null);
        }
        X x22 = y.j;
        Y.k(x22);
        x22.S();
        contentValues.put("unmatched_pfo", f.A);
        X x23 = y.j;
        Y.k(x23);
        x23.S();
        contentValues.put("unmatched_uwa", f.B);
        X x24 = y.j;
        Y.k(x24);
        x24.S();
        contentValues.put("ad_campaign_info", f.I);
        try {
            SQLiteDatabase sQLiteDatabaseO0 = O0();
            if (sQLiteDatabaseO0.update("apps", contentValues, "app_id = ?", new String[]{strC}) == 0 && sQLiteDatabaseO0.insertWithOnConflict("apps", null, contentValues, 5) == -1) {
                Y.k(i2);
                i2.g.g("Failed to insert/update app (got -1). appId", I.a0(strC));
            }
        } catch (SQLiteException e) {
            Y.k(i2);
            i2.g.h("Error storing app. appId", I.a0(strC), e);
        }
    }

    public final void p0(String str, C3881m0 c3881m0) {
        com.google.android.gms.common.internal.u.h(str);
        S();
        T();
        q0(str, W0(str));
        ContentValues contentValues = new ContentValues();
        contentValues.put("app_id", str);
        contentValues.put("storage_consent_at_bundling", c3881m0.j());
        A0(contentValues);
    }

    public final void q0(String str, C3881m0 c3881m0) {
        com.google.android.gms.common.internal.u.h(str);
        com.google.android.gms.common.internal.u.h(c3881m0);
        S();
        T();
        ContentValues contentValues = new ContentValues();
        contentValues.put("app_id", str);
        contentValues.put("consent_state", c3881m0.j());
        contentValues.put("consent_source", Integer.valueOf(c3881m0.b));
        A0(contentValues);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0066 A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean r0(java.lang.String r9) {
        /*
            r8 = this;
            java.lang.Object r0 = r8.b
            com.google.android.gms.measurement.internal.Y r0 = (com.google.android.gms.measurement.internal.Y) r0
            com.google.android.gms.measurement.internal.e r1 = r0.g
            com.google.android.gms.measurement.internal.s r2 = com.google.android.gms.measurement.internal.AbstractC3893t.M0
            r3 = 0
            boolean r1 = r1.f0(r3, r2)
            r2 = 0
            if (r1 == 0) goto L67
            com.google.android.gms.measurement.internal.s r1 = com.google.android.gms.measurement.internal.AbstractC3893t.P0
            com.google.android.gms.measurement.internal.e r0 = r0.g
            boolean r0 = r0.f0(r3, r1)
            r3 = 0
            r1 = 1
            if (r0 == 0) goto L50
            com.google.android.gms.measurement.internal.K0 r0 = com.google.android.gms.measurement.internal.K0.GOOGLE_SIGNAL
            com.google.android.gms.measurement.internal.K0[] r0 = new com.google.android.gms.measurement.internal.K0[]{r0}
            java.util.ArrayList r5 = new java.util.ArrayList
            r5.<init>(r1)
            r0 = r0[r2]
            int r0 = r0.a
            java.lang.Integer r0 = java.lang.Integer.valueOf(r0)
            r5.add(r0)
            java.lang.String r0 = B0(r5)
            java.lang.String r5 = r8.w0()
            java.lang.String r6 = "SELECT COUNT(1) > 0 FROM upload_queue WHERE app_id=?"
            java.lang.String r7 = " AND NOT "
            java.lang.String r0 = android.support.v4.media.session.a.m(r6, r0, r7, r5)
            java.lang.String[] r9 = new java.lang.String[]{r9}
            long r5 = r8.J0(r0, r9)
            int r9 = (r5 > r3 ? 1 : (r5 == r3 ? 0 : -1))
            if (r9 == 0) goto L67
            goto L66
        L50:
            java.lang.String r0 = r8.w0()
            java.lang.String[] r9 = new java.lang.String[]{r9}
            java.lang.String r5 = "SELECT COUNT(1) > 0 FROM upload_queue WHERE app_id=? AND NOT "
            java.lang.String r0 = r5.concat(r0)
            long r5 = r8.J0(r0, r9)
            int r9 = (r5 > r3 ? 1 : (r5 == r3 ? 0 : -1))
            if (r9 == 0) goto L67
        L66:
            return r1
        L67:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.r0(java.lang.String):boolean");
    }

    public final boolean s0(String str, String str2) {
        return J0("select count(1) from raw_events where app_id = ? and name = ?", new String[]{str, str2}) > 0;
    }

    public final void t0(String str, String str2) {
        com.google.android.gms.common.internal.u.e(str);
        com.google.android.gms.common.internal.u.e(str2);
        S();
        T();
        try {
            O0().delete("conditional_properties", "app_id=? and name=?", new String[]{str, str2});
        } catch (SQLiteException e) {
            Y y = (Y) this.b;
            I i2 = y.i;
            Y.k(i2);
            i2.g.i("Error deleting conditional property", I.a0(str), y.m.f(str2), e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:51:0x0127  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x012d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.measurement.internal.C3882n u0(java.lang.String r31, java.lang.String r32, java.lang.String r33) {
        /*
            Method dump skipped, instructions count: 305
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3874j.u0(java.lang.String, java.lang.String, java.lang.String):com.google.android.gms.measurement.internal.n");
    }

    public final t1 v0(String str, long j2, byte[] bArr, String str2, String str3, int i2, int i3, long j3, long j4) {
        K0 k0;
        boolean zIsEmpty = TextUtils.isEmpty(str2);
        Y y = (Y) this.b;
        if (zIsEmpty) {
            I i4 = y.i;
            Y.k(i4);
            i4.n.f("Upload uri is null or empty. Destination is unknown. Dropping batch. ");
            return null;
        }
        try {
            com.google.android.gms.internal.measurement.Z0 z0 = (com.google.android.gms.internal.measurement.Z0) M.y0(C2964a1.o(), bArr);
            K0[] k0ArrValues = K0.values();
            int length = k0ArrValues.length;
            int i5 = 0;
            while (true) {
                if (i5 >= length) {
                    k0 = K0.UNKNOWN;
                    break;
                }
                k0 = k0ArrValues[i5];
                if (k0.a == i2) {
                    break;
                }
                i5++;
            }
            if (k0 != K0.GOOGLE_SIGNAL && k0 != K0.GOOGLE_SIGNAL_PENDING && i3 > 0) {
                ArrayList arrayList = new ArrayList();
                Iterator it2 = Collections.unmodifiableList(((C2964a1) z0.b).t()).iterator();
                while (it2.hasNext()) {
                    C2969b1 c2969b1 = (C2969b1) ((C2974c1) it2.next()).f();
                    c2969b1.h();
                    C2974c1.u1((C2974c1) c2969b1.b, i3);
                    arrayList.add((C2974c1) c2969b1.f());
                }
                z0.h();
                C2964a1.w((C2964a1) z0.b);
                z0.h();
                C2964a1.u((C2964a1) z0.b, arrayList);
            }
            HashMap map = new HashMap();
            if (str3 != null) {
                String[] strArrSplit = str3.split("\r\n");
                int length2 = strArrSplit.length;
                int i6 = 0;
                while (true) {
                    if (i6 >= length2) {
                        break;
                    }
                    String str4 = strArrSplit[i6];
                    if (str4.isEmpty()) {
                        break;
                    }
                    String[] strArrSplit2 = str4.split(SimpleComparison.EQUAL_TO_OPERATION, 2);
                    if (strArrSplit2.length != 2) {
                        I i7 = y.i;
                        Y.k(i7);
                        i7.g.g("Invalid upload header: ", str4);
                        break;
                    }
                    map.put(strArrSplit2[0], strArrSplit2[1]);
                    i6++;
                }
            }
            return new t1(j2, (C2964a1) z0.f(), str2, map, k0, j3, j4, i3);
        } catch (IOException e) {
            I i8 = y.i;
            Y.k(i8);
            i8.g.h("Failed to queued MeasurementBatch from upload_queue. appId", str, e);
            return null;
        }
    }

    public final String w0() {
        ((Y) this.b).n.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        Locale locale = Locale.US;
        Long l2 = (Long) AbstractC3893t.R.a(null);
        l2.getClass();
        return AbstractC0147y.e("(", "(upload_type = 1 AND ABS(creation_timestamp - " + jCurrentTimeMillis + ") > " + l2 + ")", " OR ", android.support.v4.media.session.a.g(((Long) AbstractC3893t.Q.a(null)).longValue(), ")", androidx.compose.animation.d0.t(jCurrentTimeMillis, "(upload_type != 1 AND ABS(creation_timestamp - ", ") > ")), ")");
    }

    public final String x0(String str, String[] strArr) {
        Cursor cursorRawQuery = null;
        try {
            try {
                cursorRawQuery = O0().rawQuery(str, strArr);
                if (!cursorRawQuery.moveToFirst()) {
                    cursorRawQuery.close();
                    return "";
                }
                String string = cursorRawQuery.getString(0);
                cursorRawQuery.close();
                return string;
            } catch (SQLiteException e) {
                I i2 = ((Y) this.b).i;
                Y.k(i2);
                i2.g.h("Database error", str, e);
                throw e;
            }
        } catch (Throwable th) {
            if (cursorRawQuery != null) {
                cursorRawQuery.close();
            }
            throw th;
        }
    }

    public final void y0(String str, String str2) {
        com.google.android.gms.common.internal.u.e(str2);
        S();
        T();
        try {
            O0().delete(str, "app_id=?", new String[]{str2});
        } catch (SQLiteException e) {
            I i2 = ((Y) this.b).i;
            Y.k(i2);
            i2.g.h("Error deleting snapshot. appId", I.a0(str2), e);
        }
    }

    public final void z0(String str, C3882n c3882n) {
        Y y = (Y) this.b;
        com.google.android.gms.common.internal.u.h(c3882n);
        S();
        T();
        ContentValues contentValues = new ContentValues();
        String str2 = c3882n.a;
        contentValues.put("app_id", str2);
        contentValues.put("name", c3882n.b);
        contentValues.put("lifetime_count", Long.valueOf(c3882n.c));
        contentValues.put("current_bundle_count", Long.valueOf(c3882n.d));
        contentValues.put("last_fire_timestamp", Long.valueOf(c3882n.f));
        contentValues.put("last_bundled_timestamp", Long.valueOf(c3882n.g));
        contentValues.put("last_bundled_day", c3882n.h);
        contentValues.put("last_sampled_complex_event_id", c3882n.i);
        contentValues.put("last_sampling_rate", c3882n.j);
        contentValues.put("current_session_count", Long.valueOf(c3882n.e));
        Boolean bool = c3882n.k;
        contentValues.put("last_exempt_from_sampling", (bool == null || !bool.booleanValue()) ? null : 1L);
        try {
            if (O0().insertWithOnConflict(str, null, contentValues, 5) == -1) {
                I i2 = y.i;
                Y.k(i2);
                i2.g.g("Failed to insert/update event aggregates (got -1). appId", I.a0(str2));
            }
        } catch (SQLiteException e) {
            I i3 = y.i;
            Y.k(i3);
            i3.g.h("Error storing event aggregates. appId", I.a0(str2), e);
        }
    }
}
