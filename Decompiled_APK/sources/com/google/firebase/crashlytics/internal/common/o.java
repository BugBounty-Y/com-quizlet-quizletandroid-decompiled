package com.google.firebase.crashlytics.internal.common;

import android.content.Context;
import com.facebook.internal.y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class o implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ long c;
    public final /* synthetic */ String d;

    public /* synthetic */ o(Context context, String str, long j) {
        this.a = 2;
        this.c = j;
        this.d = str;
        this.b = context;
    }

    @Override // java.lang.Runnable
    public final void run() {
        androidx.navigation.internal.m mVar;
        switch (this.a) {
            case 0:
                q qVar = (q) this.b;
                qVar.o.b.a(new o(qVar, this.c, this.d, 1));
                break;
            case 1:
                m mVar2 = ((q) this.b).g;
                s sVar = mVar2.n;
                if (sVar == null || !sVar.e.get()) {
                    ((com.google.firebase.crashlytics.internal.metadata.d) mVar2.i.b).j(this.c, this.d);
                    break;
                }
                break;
            default:
                long j = this.c;
                String activityName = this.d;
                Context appContext = (Context) this.b;
                Intrinsics.checkNotNullParameter(activityName, "$activityName");
                androidx.navigation.internal.m mVar3 = com.facebook.appevents.internal.c.g;
                Long l = mVar3 != null ? (Long) mVar3.b : null;
                if (com.facebook.appevents.internal.c.g == null) {
                    com.facebook.appevents.internal.c.g = new androidx.navigation.internal.m(Long.valueOf(j), null);
                    String str = com.facebook.appevents.internal.c.i;
                    Intrinsics.checkNotNullExpressionValue(appContext, "appContext");
                    com.facebook.appevents.internal.m.b(appContext, activityName, str);
                } else if (l != null) {
                    long jLongValue = j - l.longValue();
                    String str2 = com.facebook.appevents.internal.c.a;
                    if (jLongValue > (y.b(com.facebook.o.b()) == null ? 60 : r4.b) * 1000) {
                        com.facebook.appevents.internal.m.d(activityName, com.facebook.appevents.internal.c.g, com.facebook.appevents.internal.c.i);
                        String str3 = com.facebook.appevents.internal.c.i;
                        Intrinsics.checkNotNullExpressionValue(appContext, "appContext");
                        com.facebook.appevents.internal.m.b(appContext, activityName, str3);
                        com.facebook.appevents.internal.c.g = new androidx.navigation.internal.m(Long.valueOf(j), null);
                    } else if (jLongValue > 1000 && (mVar = com.facebook.appevents.internal.c.g) != null) {
                        mVar.c++;
                    }
                }
                androidx.navigation.internal.m mVar4 = com.facebook.appevents.internal.c.g;
                if (mVar4 != null) {
                    mVar4.b = Long.valueOf(j);
                }
                androidx.navigation.internal.m mVar5 = com.facebook.appevents.internal.c.g;
                if (mVar5 != null) {
                    mVar5.o();
                    break;
                }
                break;
        }
    }

    public /* synthetic */ o(q qVar, long j, String str, int i) {
        this.a = i;
        this.b = qVar;
        this.c = j;
        this.d = str;
    }
}
