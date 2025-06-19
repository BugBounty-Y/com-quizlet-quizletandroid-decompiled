package com.google.firebase.sessions.settings;

import androidx.datastore.core.InterfaceC1076h;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class n {
    public static final androidx.datastore.preferences.core.f c = R6.a("firebase_sessions_enabled");
    public static final androidx.datastore.preferences.core.f d;
    public static final androidx.datastore.preferences.core.f e;
    public static final androidx.datastore.preferences.core.f f;
    public static final androidx.datastore.preferences.core.f g;
    public final InterfaceC1076h a;
    public h b;

    static {
        Intrinsics.checkNotNullParameter("firebase_sessions_sampling_rate", "name");
        d = new androidx.datastore.preferences.core.f("firebase_sessions_sampling_rate");
        e = R6.c("firebase_sessions_restart_timeout");
        f = R6.c("firebase_sessions_cache_duration");
        Intrinsics.checkNotNullParameter("firebase_sessions_cache_updated_time", "name");
        g = new androidx.datastore.preferences.core.f("firebase_sessions_cache_updated_time");
    }

    public n(InterfaceC1076h dataStore) throws Throwable {
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.a = dataStore;
        E.D(kotlin.coroutines.n.a, new k(this, null));
    }

    public static final void a(n nVar, androidx.datastore.preferences.core.b bVar) {
        nVar.getClass();
        nVar.b = new h((Boolean) bVar.c(c), (Double) bVar.c(d), (Integer) bVar.c(e), (Integer) bVar.c(f), (Long) bVar.c(g));
    }

    public final boolean b() {
        Integer num;
        h hVar = this.b;
        if (hVar == null) {
            Intrinsics.m("sessionConfigs");
            throw null;
        }
        if (hVar != null) {
            Long l = hVar.e;
            return l == null || (num = hVar.d) == null || (System.currentTimeMillis() - l.longValue()) / ((long) 1000) >= ((long) num.intValue());
        }
        Intrinsics.m("sessionConfigs");
        throw null;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(androidx.datastore.preferences.core.f r6, java.lang.Object r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r5 = this;
            boolean r0 = r8 instanceof com.google.firebase.sessions.settings.l
            if (r0 == 0) goto L13
            r0 = r8
            com.google.firebase.sessions.settings.l r0 = (com.google.firebase.sessions.settings.l) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.google.firebase.sessions.settings.l r0 = new com.google.firebase.sessions.settings.l
            r0.<init>(r5, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.io.IOException -> L27
            goto L58
        L27:
            r6 = move-exception
            goto L45
        L29:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            androidx.datastore.core.h r8 = r5.a     // Catch: java.io.IOException -> L27
            com.google.firebase.sessions.settings.m r2 = new com.google.firebase.sessions.settings.m     // Catch: java.io.IOException -> L27
            r4 = 0
            r2.<init>(r7, r6, r5, r4)     // Catch: java.io.IOException -> L27
            r0.l = r3     // Catch: java.io.IOException -> L27
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_barcode.S6.d(r8, r2, r0)     // Catch: java.io.IOException -> L27
            if (r6 != r1) goto L58
            return r1
        L45:
            java.lang.StringBuilder r7 = new java.lang.StringBuilder
            java.lang.String r8 = "Failed to update cache config value: "
            r7.<init>(r8)
            r7.append(r6)
            java.lang.String r6 = r7.toString()
            java.lang.String r7 = "SettingsCache"
            android.util.Log.w(r7, r6)
        L58:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.sessions.settings.n.c(androidx.datastore.preferences.core.f, java.lang.Object, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
