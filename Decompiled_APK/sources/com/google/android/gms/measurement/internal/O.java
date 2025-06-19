package com.google.android.gms.measurement.internal;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Pair;
import android.util.SparseArray;
import androidx.navigation.C1288j;

/* loaded from: classes2.dex */
public final class O extends AbstractC3871h0 {
    public static final Pair B = new Pair("", 0L);
    public final com.quizlet.data.interactor.progress.c A;
    public SharedPreferences d;
    public final Object e;
    public SharedPreferences f;
    public androidx.work.impl.background.greedy.d g;
    public final N h;
    public final androidx.browser.customtabs.k i;
    public String j;
    public boolean k;
    public long l;
    public final N m;
    public final C1288j n;
    public final androidx.browser.customtabs.k o;
    public final com.quizlet.data.interactor.progress.c p;
    public final C1288j q;
    public final N r;
    public final N s;
    public boolean t;
    public final C1288j u;
    public final C1288j v;
    public final N w;
    public final androidx.browser.customtabs.k x;
    public final androidx.browser.customtabs.k y;
    public final N z;

    public O(Y y) {
        super(y);
        this.e = new Object();
        this.m = new N(this, "session_timeout", 1800000L);
        this.n = new C1288j(this, "start_new_session", true);
        this.r = new N(this, "last_pause_time", 0L);
        this.s = new N(this, "session_id", 0L);
        this.o = new androidx.browser.customtabs.k(this, "non_personalized_ads");
        this.p = new com.quizlet.data.interactor.progress.c(this, "last_received_uri_timestamps_by_source");
        this.q = new C1288j(this, "allow_remote_dynamite", false);
        this.h = new N(this, "first_open_time", 0L);
        com.google.android.gms.common.internal.u.e("app_install_time");
        this.i = new androidx.browser.customtabs.k(this, "app_instance_id");
        this.u = new C1288j(this, "app_backgrounded", false);
        this.v = new C1288j(this, "deep_link_retrieval_complete", false);
        this.w = new N(this, "deep_link_retrieval_attempts", 0L);
        this.x = new androidx.browser.customtabs.k(this, "firebase_feature_rollouts");
        this.y = new androidx.browser.customtabs.k(this, "deferred_attribution_cache");
        this.z = new N(this, "deferred_attribution_cache_timestamp", 0L);
        this.A = new com.quizlet.data.interactor.progress.c(this, "default_event_parameters");
    }

    @Override // com.google.android.gms.measurement.internal.AbstractC3871h0
    public final boolean T() {
        return true;
    }

    public final SharedPreferences W() {
        S();
        U();
        if (this.f == null) {
            synchronized (this.e) {
                try {
                    if (this.f == null) {
                        Y y = (Y) this.b;
                        String str = y.a.getPackageName() + "_preferences";
                        I i = y.i;
                        Y.k(i);
                        i.o.g("Default prefs file", str);
                        this.f = y.a.getSharedPreferences(str, 0);
                    }
                } finally {
                }
            }
        }
        return this.f;
    }

    public final SharedPreferences X() {
        S();
        U();
        com.google.android.gms.common.internal.u.h(this.d);
        return this.d;
    }

    public final SparseArray Y() {
        Bundle bundleH = this.p.h();
        int[] intArray = bundleH.getIntArray("uriSources");
        long[] longArray = bundleH.getLongArray("uriTimestamps");
        if (intArray == null || longArray == null) {
            return new SparseArray();
        }
        if (intArray.length != longArray.length) {
            I i = ((Y) this.b).i;
            Y.k(i);
            i.g.f("Trigger URI source and timestamp array lengths do not match");
            return new SparseArray();
        }
        SparseArray sparseArray = new SparseArray();
        for (int i2 = 0; i2 < intArray.length; i2++) {
            sparseArray.put(intArray[i2], Long.valueOf(longArray[i2]));
        }
        return sparseArray;
    }

    public final C3881m0 Z() {
        S();
        return C3881m0.e(X().getInt("consent_source", 100), X().getString("consent_settings", "G1"));
    }

    public final void a0(boolean z) {
        S();
        I i = ((Y) this.b).i;
        Y.k(i);
        i.o.g("App measurement setting deferred collection", Boolean.valueOf(z));
        SharedPreferences.Editor editorEdit = X().edit();
        editorEdit.putBoolean("deferred_analytics_collection", z);
        editorEdit.apply();
    }

    public final boolean b0(long j) {
        return j - this.m.a() > this.r.a();
    }

    public final boolean c0(h1 h1Var) {
        S();
        String string = X().getString("stored_tcf_param", "");
        String strC = h1Var.c();
        if (strC.equals(string)) {
            return false;
        }
        SharedPreferences.Editor editorEdit = X().edit();
        editorEdit.putString("stored_tcf_param", strC);
        editorEdit.apply();
        return true;
    }
}
