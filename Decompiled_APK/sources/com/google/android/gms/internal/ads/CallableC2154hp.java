package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.pm.PackageManager;
import java.util.ArrayList;
import java.util.concurrent.Callable;

/* renamed from: com.google.android.gms.internal.ads.hp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class CallableC2154hp implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ CallableC2154hp(Tv tv) {
        this.a = 0;
        Tv tv2 = Tv.b;
        this.b = tv;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() throws PackageManager.NameNotFoundException {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                String str = (String) ((Tv) obj).a;
                Tv tv = Tv.b;
                return new C2925zo(2, str, null);
            case 1:
                return new C2109go(2, (ArrayList) ((Yn) obj).c);
            case 2:
                ((Hq) obj).mo13zza();
                return null;
            default:
                Context context = (Context) ((com.quizlet.data.repository.achievements.h) obj).a;
                return AbstractC2457os.c(context, context.getPackageName(), Integer.toString(context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionCode));
        }
    }

    public /* synthetic */ CallableC2154hp(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }
}
