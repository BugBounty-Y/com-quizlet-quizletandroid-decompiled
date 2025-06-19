package com.facebook;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import androidx.compose.foundation.lazy.layout.n0;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.J;
import com.google.android.gms.internal.mlkit_vision_common.D;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;

/* loaded from: classes.dex */
public final class f {
    public static final com.quizlet.shared.usecase.folderstudymaterials.c f = new com.quizlet.shared.usecase.folderstudymaterials.c(7);
    public static f g;
    public final androidx.localbroadcastmanager.content.b a;
    public final C1544a b;
    public AccessToken c;
    public final AtomicBoolean d;
    public Date e;

    public f(androidx.localbroadcastmanager.content.b localBroadcastManager, C1544a accessTokenCache) {
        Intrinsics.checkNotNullParameter(localBroadcastManager, "localBroadcastManager");
        Intrinsics.checkNotNullParameter(accessTokenCache, "accessTokenCache");
        this.a = localBroadcastManager;
        this.b = accessTokenCache;
        this.d = new AtomicBoolean(false);
        this.e = new Date(0L);
    }

    public final void a() {
        int i = 7;
        int i2 = 0;
        AccessToken accessToken = this.c;
        if (accessToken != null && this.d.compareAndSet(false, true)) {
            this.e = new Date();
            HashSet hashSet = new HashSet();
            HashSet hashSet2 = new HashSet();
            HashSet hashSet3 = new HashSet();
            AtomicBoolean atomicBoolean = new AtomicBoolean(false);
            n0 n0Var = new n0();
            C1545b c1545b = new C1545b(atomicBoolean, hashSet, hashSet2, hashSet3, 0);
            x xVar = x.a;
            Bundle bundle = new Bundle();
            bundle.putString("fields", "permission,status");
            String str = t.j;
            t tVarQ = assistantMode.utils.studiableMetadata.b.Q(accessToken, "me/permissions", c1545b);
            Intrinsics.checkNotNullParameter(bundle, "<set-?>");
            tVarQ.d = bundle;
            tVarQ.h = xVar;
            c cVar = new c(n0Var, i2);
            String str2 = accessToken.k;
            if (str2 == null) {
                str2 = "facebook";
            }
            e aVar = str2.equals("instagram") ? new com.quizlet.shared.usecase.srs.a(i) : new com.quizlet.shared.usecase.folderstudymaterials.d(i);
            Bundle bundle2 = new Bundle();
            bundle2.putString("grant_type", aVar.i());
            bundle2.putString("client_id", accessToken.h);
            bundle2.putString("fields", "access_token,expires_at,expires_in,data_access_expiration_time,graph_domain");
            t tVarQ2 = assistantMode.utils.studiableMetadata.b.Q(accessToken, aVar.j(), cVar);
            Intrinsics.checkNotNullParameter(bundle2, "<set-?>");
            tVarQ2.d = bundle2;
            tVarQ2.h = xVar;
            v requests = new v(tVarQ, tVarQ2);
            d callback = new d(n0Var, accessToken, atomicBoolean, hashSet, hashSet2, hashSet3, this);
            Intrinsics.checkNotNullParameter(callback, "callback");
            ArrayList arrayList = requests.d;
            if (!arrayList.contains(callback)) {
                arrayList.add(callback);
            }
            Intrinsics.checkNotNullParameter(requests, "requests");
            AbstractC1554i.i(requests);
            new u(requests).executeOnExecutor(o.c(), new Void[0]);
        }
    }

    public final void b(AccessToken accessToken, AccessToken accessToken2) {
        Intent intent = new Intent(o.a(), (Class<?>) CurrentAccessTokenExpirationBroadcastReceiver.class);
        intent.setAction("com.facebook.sdk.ACTION_CURRENT_ACCESS_TOKEN_CHANGED");
        intent.putExtra("com.facebook.sdk.EXTRA_OLD_ACCESS_TOKEN", accessToken);
        intent.putExtra("com.facebook.sdk.EXTRA_NEW_ACCESS_TOKEN", accessToken2);
        this.a.c(intent);
    }

    public final void c(AccessToken accessToken, boolean z) {
        AccessToken accessToken2 = this.c;
        this.c = accessToken;
        this.d.set(false);
        this.e = new Date(0L);
        if (z) {
            SharedPreferences sharedPreferences = this.b.a;
            if (accessToken != null) {
                Intrinsics.checkNotNullParameter(accessToken, "accessToken");
                try {
                    sharedPreferences.edit().putString("com.facebook.AccessTokenManager.CachedAccessToken", accessToken.a().toString()).apply();
                } catch (JSONException unused) {
                }
            } else {
                sharedPreferences.edit().remove("com.facebook.AccessTokenManager.CachedAccessToken").apply();
                J.c(o.a());
            }
        }
        if (accessToken2 == null ? accessToken == null : accessToken2.equals(accessToken)) {
            return;
        }
        b(accessToken2, accessToken);
        Context contextA = o.a();
        Date date = AccessToken.l;
        AccessToken accessTokenC = D.c();
        AlarmManager alarmManager = (AlarmManager) contextA.getSystemService("alarm");
        if (D.d()) {
            if ((accessTokenC != null ? accessTokenC.a : null) == null || alarmManager == null) {
                return;
            }
            Intent intent = new Intent(contextA, (Class<?>) CurrentAccessTokenExpirationBroadcastReceiver.class);
            intent.setAction("com.facebook.sdk.ACTION_CURRENT_ACCESS_TOKEN_CHANGED");
            try {
                alarmManager.set(1, accessTokenC.a.getTime(), PendingIntent.getBroadcast(contextA, 0, intent, 67108864));
            } catch (Exception unused2) {
            }
        }
    }
}
