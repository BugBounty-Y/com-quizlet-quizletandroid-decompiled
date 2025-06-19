package com.facebook.appevents.internal;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.view.View;
import com.facebook.appevents.p;
import com.facebook.internal.v;
import com.facebook.internal.y;
import com.facebook.o;
import com.skydoves.balloon.extensions.ViewExtensionKt;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;

    public /* synthetic */ a(int i, long j, String str) {
        this.a = i;
        this.b = j;
        this.c = str;
    }

    @Override // java.lang.Runnable
    public final void run() {
        int i = 1;
        switch (this.a) {
            case 0:
                long j = this.b;
                String activityName = (String) this.c;
                Intrinsics.checkNotNullParameter(activityName, "$activityName");
                if (c.g == null) {
                    c.g = new androidx.navigation.internal.m(Long.valueOf(j), null);
                }
                androidx.navigation.internal.m mVar = c.g;
                if (mVar != null) {
                    mVar.b = Long.valueOf(j);
                }
                if (c.f.get() <= 0) {
                    a aVar = new a(i, j, activityName);
                    synchronized (c.e) {
                        c.d = c.b.schedule(aVar, y.b(o.b()) == null ? 60 : r7.b, TimeUnit.SECONDS);
                        Unit unit = Unit.a;
                    }
                }
                long j2 = c.j;
                long j3 = j2 > 0 ? (j - j2) / 1000 : 0L;
                p pVar = j.a;
                Context contextA = o.a();
                v vVarK = y.k(o.b(), false);
                if (vVarK != null && vVarK.d && j3 > 0) {
                    p pVar2 = new p(contextA);
                    Bundle bundle = new Bundle(1);
                    bundle.putCharSequence("fb_aa_time_spent_view_name", activityName);
                    pVar2.a("fb_aa_time_spent_on_view", j3, bundle);
                }
                androidx.navigation.internal.m mVar2 = c.g;
                if (mVar2 != null) {
                    mVar2.o();
                    return;
                }
                return;
            case 1:
                long j4 = this.b;
                String activityName2 = (String) this.c;
                Intrinsics.checkNotNullParameter(activityName2, "$activityName");
                if (c.g == null) {
                    c.g = new androidx.navigation.internal.m(Long.valueOf(j4), null);
                }
                if (c.f.get() <= 0) {
                    m.d(activityName2, c.g, c.i);
                    SharedPreferences.Editor editorEdit = PreferenceManager.getDefaultSharedPreferences(o.a()).edit();
                    editorEdit.remove("com.facebook.appevents.SessionInfo.sessionStartTime");
                    editorEdit.remove("com.facebook.appevents.SessionInfo.sessionEndTime");
                    editorEdit.remove("com.facebook.appevents.SessionInfo.interruptionCount");
                    editorEdit.remove("com.facebook.appevents.SessionInfo.sessionId");
                    editorEdit.apply();
                    SharedPreferences.Editor editorEdit2 = PreferenceManager.getDefaultSharedPreferences(o.a()).edit();
                    editorEdit2.remove("com.facebook.appevents.SourceApplicationInfo.callingApplicationPackage");
                    editorEdit2.remove("com.facebook.appevents.SourceApplicationInfo.openedByApplink");
                    editorEdit2.apply();
                    c.g = null;
                }
                synchronized (c.e) {
                    c.d = null;
                    Unit unit2 = Unit.a;
                }
                return;
            default:
                ViewExtensionKt.circularRevealed$lambda$1((View) this.c, this.b);
                return;
        }
    }

    public /* synthetic */ a(View view, long j) {
        this.a = 2;
        this.c = view;
        this.b = j;
    }
}
