package com.google.android.gms.dynamite;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.ProviderInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.IInterface;
import android.util.Log;
import com.google.android.gms.common.internal.u;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;

/* loaded from: classes2.dex */
public final class c {
    public static Boolean g = null;
    public static String h = null;
    public static boolean i = false;
    public static int j = -1;
    public static Boolean k;
    public static g o;
    public static h p;
    public final Context a;
    public static final ThreadLocal l = new ThreadLocal();
    public static final androidx.camera.core.impl.utils.executor.b m = new androidx.camera.core.impl.utils.executor.b(7);
    public static final com.quizlet.shared.usecase.folderstudymaterials.a n = new com.quizlet.shared.usecase.folderstudymaterials.a(9);
    public static final com.quizlet.shared.usecase.folderstudymaterials.b b = new com.quizlet.shared.usecase.folderstudymaterials.b(9);
    public static final com.quizlet.shared.usecase.folderstudymaterials.c c = new com.quizlet.shared.usecase.folderstudymaterials.c(9);
    public static final com.quizlet.shared.usecase.folderstudymaterials.d d = new com.quizlet.shared.usecase.folderstudymaterials.d(9);
    public static final com.quizlet.shared.usecase.srs.a e = new com.quizlet.shared.usecase.srs.a(9);
    public static final com.quizlet.shared.usecase.studiableMetadata.a f = new com.quizlet.shared.usecase.studiableMetadata.a(9);

    public c(Context context) {
        this.a = context;
    }

    public static int a(Context context, String str) {
        try {
            ClassLoader classLoader = context.getApplicationContext().getClassLoader();
            StringBuilder sb = new StringBuilder(String.valueOf(str).length() + 61);
            sb.append("com.google.android.gms.dynamite.descriptors.");
            sb.append(str);
            sb.append(".ModuleDescriptor");
            Class<?> clsLoadClass = classLoader.loadClass(sb.toString());
            Field declaredField = clsLoadClass.getDeclaredField("MODULE_ID");
            Field declaredField2 = clsLoadClass.getDeclaredField("MODULE_VERSION");
            if (u.l(declaredField.get(null), str)) {
                return declaredField2.getInt(null);
            }
            String strValueOf = String.valueOf(declaredField.get(null));
            StringBuilder sb2 = new StringBuilder(strValueOf.length() + 50 + String.valueOf(str).length() + 1);
            sb2.append("Module descriptor id '");
            sb2.append(strValueOf);
            sb2.append("' didn't match expected id '");
            sb2.append(str);
            sb2.append("'");
            Log.e("DynamiteModule", sb2.toString());
            return 0;
        } catch (ClassNotFoundException unused) {
            StringBuilder sb3 = new StringBuilder(String.valueOf(str).length() + 45);
            sb3.append("Local module descriptor class for ");
            sb3.append(str);
            sb3.append(" not found.");
            Log.w("DynamiteModule", sb3.toString());
            return 0;
        } catch (Exception e2) {
            Log.e("DynamiteModule", "Failed to load module descriptor class: ".concat(String.valueOf(e2.getMessage())));
            return 0;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:138:0x0312 A[DONT_GENERATE] */
    /* JADX WARN: Removed duplicated region for block: B:139:0x0318 A[DONT_GENERATE] */
    /* JADX WARN: Removed duplicated region for block: B:142:0x0321 A[DONT_GENERATE] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x00cb A[Catch: all -> 0x00c0, TRY_LEAVE, TryCatch #0 {all -> 0x00c0, blocks: (B:5:0x0042, B:9:0x00b9, B:16:0x00c5, B:19:0x00cb, B:31:0x00f8, B:122:0x02a9, B:123:0x02b3, B:131:0x02c2, B:133:0x02ea, B:135:0x02fa, B:145:0x032a, B:146:0x0331, B:126:0x02b6, B:127:0x02b7, B:128:0x02be, B:147:0x0332, B:148:0x0352, B:149:0x0353, B:150:0x03a4), top: B:162:0x0042 }] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00f5  */
    /* JADX WARN: Type inference failed for: r7v1, types: [androidx.camera.core.impl.utils.executor.b, java.lang.ThreadLocal] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.dynamite.c c(android.content.Context r29, com.google.android.gms.dynamite.b r30, java.lang.String r31) throws com.google.android.gms.dynamite.DynamiteModule$LoadingException {
        /*
            Method dump skipped, instructions count: 969
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.dynamite.c.c(android.content.Context, com.google.android.gms.dynamite.b, java.lang.String):com.google.android.gms.dynamite.c");
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x01a1  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x01a4 A[Catch: all -> 0x00f4, TRY_ENTER, TRY_LEAVE, TryCatch #6 {all -> 0x00f4, blocks: (B:4:0x0006, B:64:0x00e9, B:66:0x00ef, B:73:0x011b, B:103:0x01a4, B:111:0x01b7, B:129:0x023e, B:130:0x0241, B:124:0x0236, B:71:0x00f8, B:132:0x0243, B:5:0x0007, B:8:0x000e, B:9:0x002a, B:62:0x00e6, B:22:0x004e, B:45:0x00a4, B:48:0x00a7, B:55:0x00bf, B:63:0x00e8, B:61:0x00c5), top: B:139:0x0006, inners: #4, #5 }] */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00b3 A[Catch: all -> 0x003b, TryCatch #11 {, blocks: (B:10:0x002b, B:12:0x0037, B:52:0x00bc, B:17:0x0040, B:19:0x0047, B:21:0x004d, B:26:0x0053, B:28:0x0057, B:31:0x0060, B:33:0x0068, B:36:0x006f, B:43:0x009b, B:44:0x00a3, B:39:0x0076, B:41:0x007c, B:42:0x008d, B:47:0x00a6, B:50:0x00a9, B:51:0x00b3, B:18:0x0043), top: B:144:0x002b, inners: #12 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int d(android.content.Context r13, java.lang.String r14, boolean r15) {
        /*
            Method dump skipped, instructions count: 584
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.dynamite.c.d(android.content.Context, java.lang.String, boolean):int");
    }

    public static boolean e(Context context) {
        ApplicationInfo applicationInfo;
        Boolean bool = Boolean.TRUE;
        if (bool.equals(null) || bool.equals(k)) {
            return true;
        }
        boolean z = false;
        if (k == null) {
            ProviderInfo providerInfoResolveContentProvider = context.getPackageManager().resolveContentProvider("com.google.android.gms.chimera", Build.VERSION.SDK_INT >= 29 ? 268435456 : 0);
            if (com.google.android.gms.common.c.b.c(context, 10000000) == 0 && providerInfoResolveContentProvider != null && "com.google.android.gms".equals(providerInfoResolveContentProvider.packageName)) {
                z = true;
            }
            k = Boolean.valueOf(z);
            if (z && (applicationInfo = providerInfoResolveContentProvider.applicationInfo) != null && (applicationInfo.flags & 129) == 0) {
                Log.i("DynamiteModule", "Non-system-image GmsCore APK, forcing V1");
                i = true;
            }
        }
        if (!z) {
            Log.e("DynamiteModule", "Invalid GmsCore APK, remote loading disabled.");
        }
        return z;
    }

    /* JADX WARN: Finally extract failed */
    /* JADX WARN: Removed duplicated region for block: B:124:0x00e7 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:85:0x013a A[PHI: r14
  0x013a: PHI (r14v10 boolean) = (r14v6 boolean), (r14v14 boolean) binds: [B:58:0x00f1, B:83:0x0137] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int f(android.content.Context r14, java.lang.String r15, boolean r16, boolean r17) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 413
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.dynamite.c.f(android.content.Context, java.lang.String, boolean, boolean):int");
    }

    public static void g(ClassLoader classLoader) throws DynamiteModule$LoadingException {
        try {
            h hVar = null;
            IBinder iBinder = (IBinder) classLoader.loadClass("com.google.android.gms.dynamiteloader.DynamiteLoaderV2").getConstructor(null).newInstance(null);
            if (iBinder != null) {
                IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.dynamite.IDynamiteLoaderV2");
                if (iInterfaceQueryLocalInterface instanceof h) {
                    hVar = (h) iInterfaceQueryLocalInterface;
                } else {
                    try {
                        hVar = new h(iBinder, "com.google.android.gms.dynamite.IDynamiteLoaderV2", 3);
                    } catch (IllegalAccessException e2) {
                        e = e2;
                        throw new DynamiteModule$LoadingException("Failed to instantiate dynamite loader", e);
                    } catch (InstantiationException e3) {
                        e = e3;
                        throw new DynamiteModule$LoadingException("Failed to instantiate dynamite loader", e);
                    } catch (NoSuchMethodException e4) {
                        e = e4;
                        throw new DynamiteModule$LoadingException("Failed to instantiate dynamite loader", e);
                    } catch (InvocationTargetException e5) {
                        e = e5;
                        throw new DynamiteModule$LoadingException("Failed to instantiate dynamite loader", e);
                    }
                }
            }
            p = hVar;
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException | NoSuchMethodException | InvocationTargetException e6) {
            e = e6;
        }
    }

    public static g h(Context context) {
        g gVar;
        synchronized (c.class) {
            g gVar2 = o;
            if (gVar2 != null) {
                return gVar2;
            }
            try {
                IBinder iBinder = (IBinder) context.createPackageContext("com.google.android.gms", 3).getClassLoader().loadClass("com.google.android.gms.chimera.container.DynamiteLoaderImpl").newInstance();
                if (iBinder == null) {
                    gVar = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.dynamite.IDynamiteLoader");
                    gVar = iInterfaceQueryLocalInterface instanceof g ? (g) iInterfaceQueryLocalInterface : new g(iBinder, "com.google.android.gms.dynamite.IDynamiteLoader", 3);
                }
                if (gVar != null) {
                    o = gVar;
                    return gVar;
                }
            } catch (Exception e2) {
                String message = e2.getMessage();
                StringBuilder sb = new StringBuilder(String.valueOf(message).length() + 45);
                sb.append("Failed to load IDynamiteLoader from GmsCore: ");
                sb.append(message);
                Log.e("DynamiteModule", sb.toString());
            }
            return null;
        }
    }

    public final IBinder b(String str) {
        try {
            return (IBinder) this.a.getClassLoader().loadClass(str).newInstance();
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e2) {
            throw new DynamiteModule$LoadingException("Failed to instantiate module class: ".concat(str), e2);
        }
    }
}
