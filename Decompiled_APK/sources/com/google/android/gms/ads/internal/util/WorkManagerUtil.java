package com.google.android.gms.ads.internal.util;

import android.content.Context;
import android.os.Parcel;
import androidx.annotation.NonNull;
import androidx.appcompat.app.ExecutorC0060p;
import androidx.work.C1422c;
import androidx.work.C1425f;
import androidx.work.C1437k;
import com.google.android.apps.common.proguard.UsedByReflection;
import com.google.android.gms.ads.internal.offline.buffering.OfflineNotificationPoster;
import com.google.android.gms.ads.internal.offline.buffering.OfflinePingSender;
import com.google.android.gms.ads.internal.offline.buffering.zza;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3390s2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3402v2;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class WorkManagerUtil extends AbstractBinderC2814x5 implements s {
    @UsedByReflection("This class must be instantiated reflectively so that the default class loader can be used.")
    public WorkManagerUtil() {
        super("com.google.android.gms.ads.internal.util.IWorkManagerUtil");
    }

    public static void e4(Context context) {
        try {
            Context context2 = context.getApplicationContext();
            C1422c configuration = new C1422c(new androidx.work.G());
            Intrinsics.checkNotNullParameter(context2, "context");
            Intrinsics.checkNotNullParameter(configuration, "configuration");
            androidx.work.impl.r.i(context2, configuration);
        } catch (IllegalStateException unused) {
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
            String string = parcel.readString();
            String string2 = parcel.readString();
            AbstractC2857y5.b(parcel);
            boolean zZzf = zzf(aVarV3, string, string2);
            parcel2.writeNoException();
            parcel2.writeInt(zZzf ? 1 : 0);
            return true;
        }
        if (i == 2) {
            com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
            AbstractC2857y5.b(parcel);
            zze(aVarV32);
            parcel2.writeNoException();
            return true;
        }
        if (i != 3) {
            return false;
        }
        com.google.android.gms.dynamic.a aVarV33 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
        zza zzaVar = (zza) AbstractC2857y5.a(parcel, zza.CREATOR);
        AbstractC2857y5.b(parcel);
        boolean zZzg = zzg(aVarV33, zzaVar);
        parcel2.writeNoException();
        parcel2.writeInt(zZzg ? 1 : 0);
        return true;
    }

    @Override // com.google.android.gms.ads.internal.util.s
    public final void zze(@NonNull com.google.android.gms.dynamic.a aVar) {
        Context context = (Context) com.google.android.gms.dynamic.b.I3(aVar);
        e4(context);
        try {
            Intrinsics.checkNotNullParameter(context, "context");
            androidx.work.impl.r workManagerImpl = androidx.work.impl.r.h(context);
            Intrinsics.checkNotNullExpressionValue(workManagerImpl, "getInstance(context)");
            workManagerImpl.getClass();
            Intrinsics.checkNotNullParameter("offline_ping_sender_work", "tag");
            Intrinsics.checkNotNullParameter(workManagerImpl, "workManagerImpl");
            androidx.work.B b = workManagerImpl.b.m;
            ExecutorC0060p executorC0060p = workManagerImpl.d.a;
            Intrinsics.checkNotNullExpressionValue(executorC0060p, "workManagerImpl.workTask…ecutor.serialTaskExecutor");
            AbstractC3402v2.c(b, "CancelWorkByTag_offline_ping_sender_work", executorC0060p, new androidx.work.impl.utils.a(workManagerImpl, 1));
            LinkedHashSet linkedHashSet = new LinkedHashSet();
            androidx.work.A networkType = androidx.work.A.b;
            Intrinsics.checkNotNullParameter(networkType, "networkType");
            C1425f c1425f = new C1425f(new androidx.work.impl.utils.g(null), networkType, false, false, false, false, -1L, -1L, CollectionsKt.A0(linkedHashSet));
            Intrinsics.checkNotNullParameter(OfflinePingSender.class, "workerClass");
            androidx.work.C c = (androidx.work.C) new androidx.work.C(OfflinePingSender.class).j(c1425f);
            Intrinsics.checkNotNullParameter("offline_ping_sender_work", "tag");
            ((Set) c.d).add("offline_ping_sender_work");
            workManagerImpl.b((androidx.work.D) c.a());
        } catch (IllegalStateException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Failed to instantiate WorkManager.", e);
        }
    }

    @Override // com.google.android.gms.ads.internal.util.s
    public final boolean zzf(@NonNull com.google.android.gms.dynamic.a aVar, @NonNull String str, @NonNull String str2) {
        return zzg(aVar, new zza(str, str2, ""));
    }

    @Override // com.google.android.gms.ads.internal.util.s
    public final boolean zzg(com.google.android.gms.dynamic.a aVar, zza zzaVar) {
        Context context = (Context) com.google.android.gms.dynamic.b.I3(aVar);
        e4(context);
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        androidx.work.A networkType = androidx.work.A.b;
        Intrinsics.checkNotNullParameter(networkType, "networkType");
        C1425f c1425f = new C1425f(new androidx.work.impl.utils.g(null), networkType, false, false, false, false, -1L, -1L, CollectionsKt.A0(linkedHashSet));
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        String str = zzaVar.a;
        Intrinsics.checkNotNullParameter("uri", "key");
        linkedHashMap.put("uri", str);
        Intrinsics.checkNotNullParameter("gws_query_id", "key");
        linkedHashMap.put("gws_query_id", zzaVar.b);
        Intrinsics.checkNotNullParameter("image_url", "key");
        linkedHashMap.put("image_url", zzaVar.c);
        C1437k c1437k = new C1437k(linkedHashMap);
        AbstractC3390s2.d(c1437k);
        Intrinsics.checkNotNullParameter(OfflineNotificationPoster.class, "workerClass");
        androidx.work.C c = (androidx.work.C) ((androidx.work.C) new androidx.work.C(OfflineNotificationPoster.class).j(c1425f)).k(c1437k);
        Intrinsics.checkNotNullParameter("offline_notification_work", "tag");
        ((Set) c.d).add("offline_notification_work");
        androidx.work.D d = (androidx.work.D) c.a();
        try {
            Intrinsics.checkNotNullParameter(context, "context");
            androidx.work.impl.r rVarH = androidx.work.impl.r.h(context);
            Intrinsics.checkNotNullExpressionValue(rVarH, "getInstance(context)");
            rVarH.b(d);
            return true;
        } catch (IllegalStateException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Failed to instantiate WorkManager.", e);
            return false;
        }
    }
}
