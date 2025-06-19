package com.google.android.gms.measurement.internal;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabaseLockedException;
import android.database.sqlite.SQLiteException;
import android.os.SystemClock;
import com.google.android.gms.internal.ads.Hs;
import com.google.android.gms.internal.measurement.E3;

/* renamed from: com.google.android.gms.measurement.internal.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3872i extends Hs {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ androidx.compose.animation.core.J0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3872i(C3874j c3874j, Context context) {
        super(context, "google_app_measurement.db");
        this.b = c3874j;
    }

    private final void a(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }

    private final void d(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }

    private final void f(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }

    private final void i(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final SQLiteDatabase getWritableDatabase() {
        switch (this.a) {
            case 0:
                C3874j c3874j = (C3874j) this.b;
                androidx.compose.foundation.gestures.l1 l1Var = c3874j.f;
                Y y = (Y) c3874j.b;
                y.getClass();
                if (l1Var.b != 0) {
                    ((com.google.android.gms.common.util.b) l1Var.c).getClass();
                    if (SystemClock.elapsedRealtime() - l1Var.b < 3600000) {
                        throw new SQLiteException("Database open failed");
                    }
                }
                try {
                    return super.getWritableDatabase();
                } catch (SQLiteException unused) {
                    androidx.compose.foundation.gestures.l1 l1Var2 = c3874j.f;
                    ((com.google.android.gms.common.util.b) l1Var2.c).getClass();
                    l1Var2.b = SystemClock.elapsedRealtime();
                    I i = y.i;
                    Y.k(i);
                    i.g.f("Opening the database failed, dropping and recreating it");
                    if (!y.a.getDatabasePath("google_app_measurement.db").delete()) {
                        I i2 = y.i;
                        Y.k(i2);
                        i2.g.g("Failed to delete corrupted db file", "google_app_measurement.db");
                    }
                    try {
                        SQLiteDatabase writableDatabase = super.getWritableDatabase();
                        l1Var2.b = 0L;
                        return writableDatabase;
                    } catch (SQLiteException e) {
                        I i3 = y.i;
                        Y.k(i3);
                        i3.g.g("Failed to open freshly created database", e);
                        throw e;
                    }
                }
            default:
                try {
                    return super.getWritableDatabase();
                } catch (SQLiteDatabaseLockedException e2) {
                    throw e2;
                } catch (SQLiteException unused2) {
                    C c = (C) this.b;
                    Y y2 = (Y) c.b;
                    I i4 = y2.i;
                    Y.k(i4);
                    i4.g.f("Opening the local database failed, dropping and recreating it");
                    if (!y2.a.getDatabasePath("google_app_measurement_local.db").delete()) {
                        I i5 = y2.i;
                        Y.k(i5);
                        i5.g.g("Failed to delete corrupted local db file", "google_app_measurement_local.db");
                    }
                    try {
                        return super.getWritableDatabase();
                    } catch (SQLiteException e3) {
                        I i6 = ((Y) c.b).i;
                        Y.k(i6);
                        i6.g.g("Failed to open local database. Events will bypass local storage", e3);
                        return null;
                    }
                }
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onCreate(SQLiteDatabase sQLiteDatabase) {
        switch (this.a) {
            case 0:
                I i = ((Y) ((C3874j) this.b).b).i;
                Y.k(i);
                AbstractC3883n0.f(i, sQLiteDatabase);
                break;
            default:
                I i2 = ((Y) ((C) this.b).b).i;
                Y.k(i2);
                AbstractC3883n0.f(i2, sQLiteDatabase);
                break;
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onDowngrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
        int i3 = this.a;
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onOpen(SQLiteDatabase sQLiteDatabase) throws Throwable {
        switch (this.a) {
            case 0:
                Y y = (Y) ((C3874j) this.b).b;
                I i = y.i;
                Y.k(i);
                AbstractC3883n0.c(i, sQLiteDatabase, "events", "CREATE TABLE IF NOT EXISTS events ( app_id TEXT NOT NULL, name TEXT NOT NULL, lifetime_count INTEGER NOT NULL, current_bundle_count INTEGER NOT NULL, last_fire_timestamp INTEGER NOT NULL, PRIMARY KEY (app_id, name)) ;", "app_id,name,lifetime_count,current_bundle_count,last_fire_timestamp", C3874j.g);
                I i2 = y.i;
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "events_snapshot", "CREATE TABLE IF NOT EXISTS events_snapshot ( app_id TEXT NOT NULL, name TEXT NOT NULL, lifetime_count INTEGER NOT NULL, current_bundle_count INTEGER NOT NULL, last_fire_timestamp INTEGER NOT NULL, last_bundled_timestamp INTEGER, last_bundled_day INTEGER, last_sampled_complex_event_id INTEGER, last_sampling_rate INTEGER, last_exempt_from_sampling INTEGER, current_session_count INTEGER, PRIMARY KEY (app_id, name)) ;", "app_id,name,lifetime_count,current_bundle_count,last_fire_timestamp,last_bundled_timestamp,last_bundled_day,last_sampled_complex_event_id,last_sampling_rate,last_exempt_from_sampling,current_session_count", null);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "conditional_properties", "CREATE TABLE IF NOT EXISTS conditional_properties ( app_id TEXT NOT NULL, origin TEXT NOT NULL, name TEXT NOT NULL, value BLOB NOT NULL, creation_timestamp INTEGER NOT NULL, active INTEGER NOT NULL, trigger_event_name TEXT, trigger_timeout INTEGER NOT NULL, timed_out_event BLOB,triggered_event BLOB, triggered_timestamp INTEGER NOT NULL, time_to_live INTEGER NOT NULL, expired_event BLOB, PRIMARY KEY (app_id, name)) ;", "app_id,origin,name,value,active,trigger_event_name,trigger_timeout,creation_timestamp,timed_out_event,triggered_event,triggered_timestamp,time_to_live,expired_event", null);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "user_attributes", "CREATE TABLE IF NOT EXISTS user_attributes ( app_id TEXT NOT NULL, name TEXT NOT NULL, set_timestamp INTEGER NOT NULL, value BLOB NOT NULL, PRIMARY KEY (app_id, name)) ;", "app_id,name,set_timestamp,value", C3874j.i);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "apps", "CREATE TABLE IF NOT EXISTS apps ( app_id TEXT NOT NULL, app_instance_id TEXT, gmp_app_id TEXT, resettable_device_id_hash TEXT, last_bundle_index INTEGER NOT NULL, last_bundle_end_timestamp INTEGER NOT NULL, PRIMARY KEY (app_id)) ;", "app_id,app_instance_id,gmp_app_id,resettable_device_id_hash,last_bundle_index,last_bundle_end_timestamp", C3874j.j);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "queue", "CREATE TABLE IF NOT EXISTS queue ( app_id TEXT NOT NULL, bundle_end_timestamp INTEGER NOT NULL, data BLOB NOT NULL);", "app_id,bundle_end_timestamp,data", C3874j.l);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "raw_events_metadata", "CREATE TABLE IF NOT EXISTS raw_events_metadata ( app_id TEXT NOT NULL, metadata_fingerprint INTEGER NOT NULL, metadata BLOB NOT NULL, PRIMARY KEY (app_id, metadata_fingerprint));", "app_id,metadata_fingerprint,metadata", null);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "raw_events", "CREATE TABLE IF NOT EXISTS raw_events ( app_id TEXT NOT NULL, name TEXT NOT NULL, timestamp INTEGER NOT NULL, metadata_fingerprint INTEGER NOT NULL, data BLOB NOT NULL);", "app_id,name,timestamp,metadata_fingerprint,data", C3874j.k);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "event_filters", "CREATE TABLE IF NOT EXISTS event_filters ( app_id TEXT NOT NULL, audience_id INTEGER NOT NULL, filter_id INTEGER NOT NULL, event_name TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY (app_id, event_name, audience_id, filter_id));", "app_id,audience_id,filter_id,event_name,data", C3874j.m);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "property_filters", "CREATE TABLE IF NOT EXISTS property_filters ( app_id TEXT NOT NULL, audience_id INTEGER NOT NULL, filter_id INTEGER NOT NULL, property_name TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY (app_id, property_name, audience_id, filter_id));", "app_id,audience_id,filter_id,property_name,data", C3874j.n);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "audience_filter_values", "CREATE TABLE IF NOT EXISTS audience_filter_values ( app_id TEXT NOT NULL, audience_id INTEGER NOT NULL, current_results BLOB, PRIMARY KEY (app_id, audience_id));", "app_id,audience_id,current_results", null);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "app2", "CREATE TABLE IF NOT EXISTS app2 ( app_id TEXT NOT NULL, first_open_count INTEGER NOT NULL, PRIMARY KEY (app_id));", "app_id,first_open_count", C3874j.o);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "main_event_params", "CREATE TABLE IF NOT EXISTS main_event_params ( app_id TEXT NOT NULL, event_id TEXT NOT NULL, children_to_process INTEGER NOT NULL, main_event BLOB NOT NULL, PRIMARY KEY (app_id));", "app_id,event_id,children_to_process,main_event", null);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "default_event_params", "CREATE TABLE IF NOT EXISTS default_event_params ( app_id TEXT NOT NULL, parameters BLOB NOT NULL, PRIMARY KEY (app_id));", "app_id,parameters", null);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "consent_settings", "CREATE TABLE IF NOT EXISTS consent_settings ( app_id TEXT NOT NULL, consent_state TEXT NOT NULL, PRIMARY KEY (app_id));", "app_id,consent_state", C3874j.p);
                E3.b();
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "trigger_uris", "CREATE TABLE IF NOT EXISTS trigger_uris ( app_id TEXT NOT NULL, trigger_uri TEXT NOT NULL, timestamp_millis INTEGER NOT NULL, source INTEGER NOT NULL);", "app_id,trigger_uri,source,timestamp_millis", C3874j.q);
                Y.k(i2);
                AbstractC3883n0.c(i2, sQLiteDatabase, "upload_queue", "CREATE TABLE IF NOT EXISTS upload_queue ( app_id TEXT NOT NULL, upload_uri TEXT NOT NULL, upload_headers TEXT NOT NULL, upload_type INTEGER NOT NULL, measurement_batch BLOB NOT NULL, retry_count INTEGER NOT NULL, creation_timestamp INTEGER NOT NULL );", "app_id,upload_uri,upload_headers,upload_type,measurement_batch,retry_count,creation_timestamp", C3874j.h);
                break;
            default:
                I i3 = ((Y) ((C) this.b).b).i;
                Y.k(i3);
                AbstractC3883n0.c(i3, sQLiteDatabase, "messages", "create table if not exists messages ( type INTEGER NOT NULL, entry BLOB NOT NULL)", "type,entry", C.f);
                break;
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
        int i3 = this.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3872i(C c, Context context) {
        super(context, "google_app_measurement_local.db");
        this.b = c;
    }
}
