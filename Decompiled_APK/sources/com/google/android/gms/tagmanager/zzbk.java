package com.google.android.gms.tagmanager;

import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.dynamic.b;
import com.google.android.gms.dynamite.DynamiteModule$LoadingException;
import com.google.android.gms.dynamite.c;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.tagmanager.ModuleDescriptor;
import com.google.android.gms.measurement.AppMeasurement;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
abstract class zzbk {
    private static volatile c zza;
    private static volatile zzcn zzb;
    private static final Map zzc = new HashMap();
    private static final Map zzd = new HashMap();

    public static IBinder zza(Context context) {
        try {
            try {
                return zzcp.asInterface(zzg(context).b("com.google.android.gms.tagmanager.TagManagerServiceProviderImpl")).getService(new b(context), zzh(context), new zzbj()).asBinder();
            } catch (RemoteException e) {
                throw new IllegalStateException(e);
            }
        } catch (DynamiteModule$LoadingException e2) {
            throw new RuntimeException(e2);
        }
    }

    public static void zze(Context context) {
        zzcn zzcnVarZzi = zzi(context);
        synchronized (zzbk.class) {
            try {
                try {
                    zzcnVarZzi.initialize(new b(context), zzh(context), new zzbj());
                } catch (RemoteException e) {
                    throw new IllegalStateException(e);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static void zzf(Intent intent, Context context) {
        zzcn zzcnVarZzi = zzi(context);
        synchronized (zzbk.class) {
            try {
                try {
                    zzcnVarZzi.previewIntent(intent, new b(context), new b(zza.a), zzh(context), new zzbj());
                } catch (RemoteException e) {
                    throw new IllegalStateException(e);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    private static c zzg(Context context) throws DynamiteModule$LoadingException {
        c cVarC;
        c cVar = zza;
        if (cVar != null) {
            return cVar;
        }
        synchronized (zzbk.class) {
            try {
                cVarC = zza;
                if (zza == null) {
                    cVarC = c.c(context, c.f, ModuleDescriptor.MODULE_ID);
                    zza = cVarC;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return cVarC;
    }

    private static zzck zzh(Context context) {
        return new zzbi(AppMeasurement.getInstance(context));
    }

    private static zzcn zzi(Context context) {
        zzcn zzcnVarAsInterface;
        zzcn zzcnVar = zzb;
        if (zzcnVar != null) {
            return zzcnVar;
        }
        synchronized (zzbk.class) {
            zzcnVarAsInterface = zzb;
            if (zzcnVarAsInterface == null) {
                try {
                    zzcnVarAsInterface = zzcm.asInterface(zzg(context).b("com.google.android.gms.tagmanager.TagManagerApiImpl"));
                    zzb = zzcnVarAsInterface;
                } catch (DynamiteModule$LoadingException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return zzcnVarAsInterface;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static Object zzj(String str, Class cls) throws ClassNotFoundException {
        try {
            Class<?> cls2 = Class.forName(str);
            for (Class<?> cls3 : cls2.getInterfaces()) {
                if (cls3.equals(cls)) {
                    try {
                        try {
                            try {
                                return cls2.getConstructor(null).newInstance(null);
                            } catch (SecurityException unused) {
                                Log.e("GoogleTagManagerAPI", str + " doesn't have an accessible no-arg constructor");
                                return null;
                            }
                        } catch (IllegalAccessException unused2) {
                            Log.e("GoogleTagManagerAPI", str + " doesn't have an accessible no-arg constructor");
                            return null;
                        } catch (InvocationTargetException unused3) {
                            Log.e("GoogleTagManagerAPI", str + " construction threw an exception.");
                            return null;
                        }
                    } catch (InstantiationException unused4) {
                        Log.e("GoogleTagManagerAPI", str + " is an abstract class.");
                        return null;
                    } catch (NoSuchMethodException unused5) {
                        Log.e("GoogleTagManagerAPI", str + " doesn't have a valid no-arg constructor");
                        return null;
                    }
                }
            }
            Log.e("GoogleTagManagerAPI", str + " doesn't implement " + cls.getCanonicalName() + " interface.");
            return null;
        } catch (ClassNotFoundException unused6) {
            Log.e("GoogleTagManagerAPI", String.valueOf(str).concat(" can't be found in the application."));
        }
    }
}
