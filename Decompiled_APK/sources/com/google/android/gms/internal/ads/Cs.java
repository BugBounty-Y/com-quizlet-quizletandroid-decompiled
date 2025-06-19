package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import com.google.android.gms.ads.internal.client.C1608n;
import dalvik.system.DexClassLoader;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class Cs {
    public static final HashMap f = new HashMap();
    public final Context a;
    public final androidx.compose.ui.node.V b;
    public final androidx.browser.customtabs.k c;
    public com.quizlet.data.repository.explanations.exercise.b d;
    public final Object e = new Object();

    public Cs(Context context, androidx.compose.ui.node.V v, androidx.browser.customtabs.k kVar, C1 c1) {
        this.a = context;
        this.b = v;
        this.c = kVar;
    }

    public final com.quizlet.data.repository.explanations.exercise.b a() {
        com.quizlet.data.repository.explanations.exercise.b bVar;
        synchronized (this.e) {
            bVar = this.d;
        }
        return bVar;
    }

    public final boolean b(C1608n c1608n) throws IllegalAccessException, InstantiationException, zzfps, IllegalArgumentException, InvocationTargetException {
        long jCurrentTimeMillis = System.currentTimeMillis();
        try {
            try {
                com.quizlet.data.repository.explanations.exercise.b bVar = new com.quizlet.data.repository.explanations.exercise.b(c(c1608n).getDeclaredConstructor(Context.class, String.class, byte[].class, Object.class, Bundle.class, Integer.TYPE).newInstance(this.a, "msa-r", c1608n.x(), null, new Bundle(), 2), c1608n, this.b, this.c);
                if (!bVar.l()) {
                    throw new zzfps(4000, "init failed");
                }
                int iJ = bVar.j();
                if (iJ != 0) {
                    throw new zzfps(4001, "ci: " + iJ);
                }
                synchronized (this.e) {
                    com.quizlet.data.repository.explanations.exercise.b bVar2 = this.d;
                    if (bVar2 != null) {
                        try {
                            bVar2.k();
                        } catch (zzfps e) {
                            this.c.r(e.a, -1L, e);
                        }
                        this.d = bVar;
                    } else {
                        this.d = bVar;
                    }
                }
                this.c.s(3000, System.currentTimeMillis() - jCurrentTimeMillis);
                return true;
            } catch (Exception e2) {
                throw new zzfps(2004, e2);
            }
        } catch (zzfps e3) {
            this.c.r(e3.a, System.currentTimeMillis() - jCurrentTimeMillis, e3);
            return false;
        } catch (Exception e4) {
            this.c.r(4010, System.currentTimeMillis() - jCurrentTimeMillis, e4);
            return false;
        }
    }

    public final synchronized Class c(C1608n c1608n) {
        try {
            String strE = ((C2728v5) c1608n.a).E();
            HashMap map = f;
            Class cls = (Class) map.get(strE);
            if (cls != null) {
                return cls;
            }
            try {
                if (!C1.u((File) c1608n.b)) {
                    throw new zzfps(2026, "VM did not pass signature verification");
                }
                try {
                    File file = (File) c1608n.c;
                    if (!file.exists()) {
                        file.mkdirs();
                    }
                    Class<?> clsLoadClass = new DexClassLoader(((File) c1608n.b).getAbsolutePath(), file.getAbsolutePath(), null, this.a.getClassLoader()).loadClass("com.google.ccc.abuse.droidguard.DroidGuard");
                    map.put(strE, clsLoadClass);
                    return clsLoadClass;
                } catch (ClassNotFoundException e) {
                    e = e;
                    throw new zzfps(2008, e);
                } catch (IllegalArgumentException e2) {
                    e = e2;
                    throw new zzfps(2008, e);
                } catch (SecurityException e3) {
                    e = e3;
                    throw new zzfps(2008, e);
                }
            } catch (GeneralSecurityException e4) {
                throw new zzfps(2026, e4);
            }
        } finally {
        }
    }
}
