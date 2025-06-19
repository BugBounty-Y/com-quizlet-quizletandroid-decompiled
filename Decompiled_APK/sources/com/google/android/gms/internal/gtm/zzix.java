package com.google.android.gms.internal.gtm;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.Uri;
import android.os.RemoteException;
import android.util.Pair;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.stats.a;
import java.io.File;
import java.io.IOException;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class zzix {
    private static final Pattern zza = Pattern.compile("(gtm-[a-z0-9]{1,10})\\.json", 2);
    private static volatile zzix zzb;
    private final Context zzc;
    private final com.google.android.gms.tagmanager.zzck zzd;
    private final zzjg zze;
    private final ExecutorService zzf;
    private final ScheduledExecutorService zzg;
    private final zzhp zzh;
    private final zzit zzi;
    private String zzk;
    private String zzl;
    private final Object zzj = new Object();
    private int zzm = 1;
    private final Queue zzn = new LinkedList();
    private volatile boolean zzo = false;
    private volatile boolean zzp = false;

    public zzix(Context context, com.google.android.gms.tagmanager.zzck zzckVar, com.google.android.gms.tagmanager.zzcb zzcbVar, zzjg zzjgVar, ExecutorService executorService, ScheduledExecutorService scheduledExecutorService, zzhp zzhpVar, zzit zzitVar) {
        u.h(context);
        u.h(zzckVar);
        this.zzc = context;
        this.zzd = zzckVar;
        this.zze = zzjgVar;
        this.zzf = executorService;
        this.zzg = scheduledExecutorService;
        this.zzh = zzhpVar;
        this.zzi = zzitVar;
    }

    public static zzix zzf(Context context, com.google.android.gms.tagmanager.zzck zzckVar, com.google.android.gms.tagmanager.zzcb zzcbVar) {
        zzix zzixVar;
        u.h(context);
        zzix zzixVar2 = zzb;
        if (zzixVar2 != null) {
            return zzixVar2;
        }
        synchronized (zzix.class) {
            try {
                zzixVar = zzb;
                if (zzixVar == null) {
                    zzix zzixVar3 = new zzix(context, zzckVar, zzcbVar, new zzjg(context, a.b()), zzjd.zza(context), zzjf.zza, zzhp.zza(), new zzit(context));
                    zzb = zzixVar3;
                    zzixVar = zzixVar3;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return zzixVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final Pair zzp(String[] strArr) {
        String str;
        zzhi.zzd("Looking up container asset.");
        String str2 = this.zzk;
        if (str2 != null && (str = this.zzl) != null) {
            return Pair.create(str2, str);
        }
        try {
            String[] strArrZzb = this.zzi.zzb("containers");
            boolean z = false;
            for (int i = 0; i < strArrZzb.length; i++) {
                Pattern pattern = zza;
                Matcher matcher = pattern.matcher(strArrZzb[i]);
                if (matcher.matches()) {
                    if (z) {
                        zzhi.zze("Extra container asset found, will not be loaded: ".concat(String.valueOf(strArrZzb[i])));
                    } else {
                        this.zzk = matcher.group(1);
                        this.zzl = android.support.v4.media.session.a.B("containers", File.separator, strArrZzb[i]);
                        zzhi.zzd("Asset found for container ".concat(String.valueOf(this.zzk)));
                    }
                    z = true;
                } else {
                    zzhi.zze("Ignoring container asset " + strArrZzb[i] + " (does not match " + pattern.pattern() + ")");
                }
            }
            if (!z) {
                zzhi.zze("No container asset found in /assets/containers. Checking top level /assets directory for container assets.");
                try {
                    String[] strArrZza = this.zzi.zza();
                    boolean z2 = false;
                    for (int i2 = 0; i2 < strArrZza.length; i2++) {
                        Matcher matcher2 = zza.matcher(strArrZza[i2]);
                        if (matcher2.matches()) {
                            if (z2) {
                                zzhi.zze("Extra container asset found, will not be loaded: ".concat(String.valueOf(strArrZza[i2])));
                            } else {
                                String strGroup = matcher2.group(1);
                                this.zzk = strGroup;
                                this.zzl = strArrZza[i2];
                                zzhi.zzd("Asset found for container ".concat(String.valueOf(strGroup)));
                                zzhi.zze("Loading container assets from top level /assets directory. Please move the container asset to /assets/containers");
                                z2 = true;
                            }
                        }
                    }
                } catch (IOException e) {
                    zzhi.zzb("Failed to enumerate assets.", e);
                    return Pair.create(null, null);
                }
            }
            return Pair.create(this.zzk, this.zzl);
        } catch (IOException e2) {
            zzhi.zzb("Failed to enumerate assets in folder containers", e2);
            return Pair.create(null, null);
        }
    }

    public final void zzm(String[] strArr) {
        zzhi.zzd("Initializing Tag Manager.");
        long jCurrentTimeMillis = System.currentTimeMillis();
        synchronized (this.zzj) {
            if (this.zzo) {
                return;
            }
            try {
                Context context = this.zzc;
                try {
                    ServiceInfo serviceInfo = context.getPackageManager().getServiceInfo(new ComponentName(context.getPackageName(), "com.google.android.gms.tagmanager.TagManagerService"), 0);
                    if (serviceInfo != null) {
                        if (serviceInfo.enabled) {
                            Pair pairZzp = zzp(null);
                            String str = (String) pairZzp.first;
                            String str2 = (String) pairZzp.second;
                            if (str == null || str2 == null) {
                                zzhi.zze("Tag Manager's event handler WILL NOT be installed (no container loaded)");
                            } else {
                                zzhi.zzc("Loading container ".concat(str));
                                this.zzf.execute(new zzin(this, str, str2, null));
                                this.zzg.schedule(new zzip(this), 5000L, TimeUnit.MILLISECONDS);
                                if (!this.zzp) {
                                    zzhi.zzc("Installing Tag Manager event handler.");
                                    this.zzp = true;
                                    try {
                                        this.zzd.zze(new zzik(this));
                                    } catch (RemoteException e) {
                                        zzgp.zzb("Error communicating with measurement proxy: ", e, this.zzc);
                                    }
                                    try {
                                        this.zzd.zzd(new zzim(this));
                                    } catch (RemoteException e2) {
                                        zzgp.zzb("Error communicating with measurement proxy: ", e2, this.zzc);
                                    }
                                    this.zzc.registerComponentCallbacks(new zzir(this));
                                    zzhi.zzc("Tag Manager event handler installed.");
                                }
                            }
                            zzhi.zzc("Tag Manager initialization took " + (System.currentTimeMillis() - jCurrentTimeMillis) + "ms");
                            return;
                        }
                    }
                } catch (PackageManager.NameNotFoundException unused) {
                }
                zzhi.zze("Tag Manager fails to initialize (TagManagerService not enabled in the manifest)");
            } finally {
                this.zzo = true;
            }
        }
    }

    public final void zzn(Uri uri) {
        this.zzf.execute(new zzis(this, uri));
    }
}
