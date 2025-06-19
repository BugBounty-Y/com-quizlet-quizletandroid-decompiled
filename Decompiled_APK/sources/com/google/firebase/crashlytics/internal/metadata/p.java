package com.google.firebase.crashlytics.internal.metadata;

import android.util.Log;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class p {
    public final ArrayList a;
    public int b;

    public p(int i) {
        switch (i) {
            case 1:
                this.a = new ArrayList();
                this.b = 0;
                break;
            default:
                this.a = new ArrayList();
                this.b = 128;
                break;
        }
    }

    public void a(com.squareup.moshi.k kVar) {
        ArrayList arrayList = this.a;
        int i = this.b;
        this.b = i + 1;
        arrayList.add(i, kVar);
    }

    public synchronized List b() {
        return Collections.unmodifiableList(new ArrayList(this.a));
    }

    public boolean c() {
        return this.b < this.a.size();
    }

    public synchronized boolean d(List list) {
        this.a.clear();
        if (list.size() <= this.b) {
            return this.a.addAll(list);
        }
        Log.w("FirebaseCrashlytics", "Ignored 0 entries when adding rollout assignments. Maximum allowable: " + this.b, null);
        return this.a.addAll(list.subList(0, this.b));
    }

    public p(ArrayList routes) {
        Intrinsics.checkNotNullParameter(routes, "routes");
        this.a = routes;
    }
}
