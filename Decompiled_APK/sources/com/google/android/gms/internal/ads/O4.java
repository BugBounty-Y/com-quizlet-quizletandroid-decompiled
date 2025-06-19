package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.net.NetworkCapabilities;
import android.os.Looper;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.view.MotionEvent;
import android.view.View;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class O4 implements N4 {
    public static long A = 0;
    public static S4 B = null;
    public static C2039f5 C = null;
    public static J D = null;
    public static C2326lq E = null;
    public static S4 F = null;
    public static volatile Z4 x = null;
    public static final Object y = new Object();
    public static boolean z = false;
    public MotionEvent a;
    public double j;
    public double k;
    public double l;
    public float m;
    public float n;
    public float o;
    public float p;
    public final DisplayMetrics s;
    public final C2881yn t;
    public final com.bumptech.glide.manager.p u;
    public ViewOnAttachStateChangeListenerC1952d5 v;
    public final HashMap w;
    public final LinkedList b = new LinkedList();
    public long c = 0;
    public long d = 0;
    public long e = 0;
    public long f = 0;
    public long g = 0;
    public long h = 0;
    public long i = 0;
    public boolean q = false;
    public boolean r = false;

    public O4(Context context, com.bumptech.glide.manager.p pVar) {
        try {
            D4.b();
            this.s = context.getResources().getDisplayMetrics();
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U2)).booleanValue()) {
                this.t = new C2881yn(5);
            }
        } catch (Throwable unused) {
        }
        this.w = new HashMap();
        this.u = pVar;
    }

    public static Z4 o(Context context, boolean z2) {
        if (x == null) {
            synchronized (y) {
                try {
                    if (x == null) {
                        Z4 z4C = Z4.c(context, z2, F);
                        if (z4C.n) {
                            try {
                                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.t3)).booleanValue()) {
                                    z4C.e("y8u27MPWCVJsG3YIVgYnxR1WDIIu4BZQFVaGyDrrpb6j9mGUdDYoUspcK04essTY", "SnsJ9v5CQU1bwP72mSUEQMmHIpBjUeN/3q4xxExFyR4=", new Class[0]);
                                }
                            } catch (IllegalStateException unused) {
                            }
                            z4C.e("3Zl/jsONipIdXfYzySYAkSVl4tnZ97yL+dpm5guin6XqtlL76x2RBs1pekZbrWj3", "RazLrJuj66rEYi0Ba83KDPVF1jzAxv8EAf2Frt5YaIg=", Context.class);
                            z4C.e("agDdf5wrmtJ0cP5XVK0JCsJ4BViR17o/n9P6hmH0muvYwmpx2DZ552/tAJvOo6qR", "48yXjRp5G93PEoVZx8WBMAeqgOhil0yQSUdmW98nZyI=", Context.class);
                            z4C.e("G1O+5tqulLBNCxZxcYiJSAGrazgAMWmQ49z8g8PEPhhOgnBizp9p2UWwJMiSx+ju", "xfUFYLaeYlsk7z1gy27YVxCq/UzpfsdVkNtosT4BuNc=", Context.class);
                            z4C.e("ptULCqFpkxWHwh0HVZoMpk0Xr91rKWbEROvrSrbrHF8bfcD+J1G9qxssmqT2HcO0", "gABvx04l+Prrr7UIzRlxJTdbXEyGkYLmeTdDcw+INuA=", Context.class);
                            z4C.e("8IJIsIBlDz5+1RGl+6kTNxKhKd20laJu7Ry/q2vMjbAxuJnkIuDVJXV0JiVYkZ0x", "TGJcgVVlBzpT0hARXkl1Qb1oxDrm3oU5utV1aupQqoE=", Context.class);
                            Class cls = Boolean.TYPE;
                            z4C.e("+T/U1hw7+KZ4U7a2mmAOu7BJ15632T6q77fmzX/Xgjcy3uK841Ng+VsVpINIYuXP", "GzjxqsxzxT+aATwD+mE+LGwR24OtaI/aqws6qGNlH18=", Context.class, cls);
                            z4C.e("1BnW1+pN8ACAA5SCwHeu4aDyUa+GdAsZQaTQjOE/fWA7hyCouT0ju5bDmhkUNXUI", "kp4jwXczzGPw0lGC8OB8RleYASbnnNEZzgNaMBT0Bfw=", Context.class);
                            z4C.e("WQkp0526ddrUi1BRkagos9QKSJQ1uugrJcxnlXdGVtysNEwcyhf7H4AuLi1Daa/J", "bIxRlixcWzGpKi+RzORPGFA/CCK1ebxNEgd5yxb9Upc=", Context.class);
                            z4C.e("L8xVO+KaaDA3r3acgbwvVAQfORMu/AO/jc+P7Gm7GVrn51wWH/CUynJHZ2tWyb88", "cA0h1lVVQMOm5i8Ftty3JhPXQ/C7ZIGa6qN3R34rFvI=", MotionEvent.class, DisplayMetrics.class);
                            z4C.e("MzsWIz4gfLj0a3R+qdHFnq4+xme2LarFguHCIutZgqcm6GnV+OetVQKtggSwCSnr", "3rH82U9H9h0NHlfre8U+glRveAN0QJ52a1RA+MBgcOg=", MotionEvent.class, DisplayMetrics.class);
                            z4C.e("bz3lIaHWpCquphICM8d57wBZcB7vA3QBLpLSSF22FzCVTv7HI8nqsTojeybBUatg", "nJy2u10FH1OsIt1ONuXNmQ7d3Q3+he826LogUVDBAds=", new Class[0]);
                            z4C.e("AkswGwusnlvibekdTn6rp1TLruqBIpT26qUqw6ERX2GI+0q3NNodYWGNobvk/KA0", "+ySS/EYovSzthax5b5cNVBSw7OeHS3QqC5FfLg20T6g=", new Class[0]);
                            z4C.e("d4PN2fwB2P9jxIUN6NPwGCD1vcjTZd510+VTbYWnWivlqPuX4Pd9jb/zoaClHGV2", "B7r3opNSMuM8FMoC6aVwUNpehxdhrcT61rhsqayMJbM=", new Class[0]);
                            z4C.e("n8+dbEkb8sSSkj8RrAZPAIBpRkB5kUln+00UVnn84X80gYgRIiK8WSxHPJEqxXHc", "yKnJQpgvAxtK/oRpf77IDthT8ZJJ6VXKsBNJ0lMvjYQ=", new Class[0]);
                            z4C.e("2yqQbpMMcqKX38M442dN+dCyzykwnAxluzbiBDnzfSZwwykVdh1BxKbQaA6qVZBU", "1XIQFsxUhHfLRHhylour2btyczZCL08SFkmijCbkayQ=", new Class[0]);
                            z4C.e("ZfusKpZJ8SBLRBp0x6BWNud7pIzhvWIkVd0V0uxTu84aE2cfWFwKn+FMoh4smXgk", "VN0WZ1yYObu9EYHkfC3f48JbFLjOwnUEkH1X8nPNLSU=", new Class[0]);
                            z4C.e("5l2BxulTXy+0Wovy9T0xreNvMgccuxz9Mfzqj2nIzDWreku9cf/hyHYbFP2gke7n", "rfz55QLsxMWzB2XqDjYWCElC2tXCWyMh5Hq3cP2KfWk=", Context.class, cls, String.class);
                            z4C.e("UtW7g7feJqOHsjIRMP7TbkL8M4VYsmVrsaULCIKJGwvBOELKcxTQZfT6AHg6wl4V", "3s4OpKjyDjUzqtut1o8wCVCKFRdtRePXWRu+sqk/xG8=", StackTraceElement[].class);
                            z4C.e("h7NW4UTeHoapcAfHjNS1jSIEsdu+S9XbBUhqH3zqKlRoFqG3FEF52d6iyzd+cmzU", "UQVAYGHTy6RzP6i5dxbs04Nz2BVdis2XDzzm3D3JwpQ=", View.class, DisplayMetrics.class, cls, cls);
                            z4C.e("jIv42z2v6FXxayFh75bTXtsxRSsCK/ciQjkFKmgks8cLq7HP+HDebRZyGvyOBC97", "2wHbvH170oRSgA6rj2BMxMfMsZs+WbUtizDquheRwWE=", Context.class, cls);
                            z4C.e("YX3pd3fZ/j0e82Z3yXv98nYqAI3nsN+d0YAKVHjoLLbjd+BRZ45hNatoujYNmZM/", "2IfMUy5zOuVT1ilWAqZrt9PNbHCY94WGDxwYlYOFZTM=", View.class, Activity.class, cls);
                            z4C.e("YdsvNQpLn71zCPsmNiBmaxgvKAoUotN+t67Ej8NmXEez61kI/ElwL7USsI8xuH+E", "BTo9KBR1VAIklcWQcnKn1k6hpYvG+18rom++PUlQVcU=", Long.TYPE);
                            z4C.e("G6tpJfcfsXNaUQhDJn9Qju0vku5y/oa1fF8zdhZ2CFQQ0yJpdIBybAnW8Cnq7FGe", "fIK5mOsPYa+LmT3H4ctpyCeP1IjF5A1bfJROt5z4ppI=", new Class[0]);
                            try {
                                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.w3)).booleanValue()) {
                                    z4C.e("4HRSTLOwWZkuNJXWodn1qJJgWaIIvv19EC2kc5Tc35PPh8H51LV3J7XsfwYf6N8B", "x59qZ2C8s/H9o8A43vx+gBO6K2fFzzXR0hkzA9nrVNs=", Context.class);
                                }
                            } catch (IllegalStateException unused2) {
                            }
                            z4C.e("dRD+JVHrAp9KS52Ek5z+07PqwexnB2SlEw3dstFC/1pUdbIUHq4sOL+yEg/9GhsH", "AVj0chiCvO7NARSM7gnUx+yq9iwGX0sKyhH1s5c2UEE=", Context.class);
                            try {
                                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.x3)).booleanValue()) {
                                    Class cls2 = Long.TYPE;
                                    z4C.e("Q2alXHIIp2vvtZN4ZNw4W3dXvS5FZxkSx8F3noC2XP6gq0/XB0ulYQV32h8ZSW0i", "bHzouddPHTqhUNsOeni/FRK++KVVMe5yU+yUqilZ/gg=", NetworkCapabilities.class, cls2, cls2);
                                }
                            } catch (IllegalStateException unused3) {
                            }
                            try {
                                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U2)).booleanValue()) {
                                    z4C.e("LLos9e8Ql/sv7oIXEM/FCVf2w4qxksYVSJjnFOiKAZfJ/fOB+3TAGyZw1OkiJRsU", "lmzfMnrRinUoapvwdylnImZxEAh1S0BzbHZ4/bdyts0=", List.class);
                                }
                            } catch (IllegalStateException unused4) {
                            }
                            try {
                            } catch (IllegalStateException unused5) {
                            }
                            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.M2)).booleanValue()) {
                                Class cls3 = Long.TYPE;
                                z4C.e("L3kNtlg7QY6D9Xl7pPswVVS/MCBOYXcB4vflYd8GjH187tfdUwj4wLKq5xN70kha", "7KShiw4CrXn9e1sAZ1bf68KLoTIikFllvC3ALPO42ag=", cls3, cls3, cls3, cls3);
                            } else {
                                try {
                                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.L2)).booleanValue()) {
                                        z4C.e("q8irn8XqClynUBOsRuq73Jawzwc3gJeVDnk3iDYtMcevrbEAuNWFzcNhN+feXrfp", "dam+Wb9GR7yMSr36KIsK6PGM3yrtzGfNR9lAtk4lliE=", long[].class, Context.class, View.class);
                                    }
                                } catch (IllegalStateException unused6) {
                                }
                            }
                        }
                        x = z4C;
                    }
                } finally {
                }
            }
        }
        return x;
    }

    public static C1821a5 q(Z4 z4, MotionEvent motionEvent, DisplayMetrics displayMetrics) throws zzawe {
        Method methodD = z4.d("L8xVO+KaaDA3r3acgbwvVAQfORMu/AO/jc+P7Gm7GVrn51wWH/CUynJHZ2tWyb88", "cA0h1lVVQMOm5i8Ftty3JhPXQ/C7ZIGa6qN3R34rFvI=");
        if (methodD == null || motionEvent == null) {
            throw new zzawe();
        }
        try {
            return new C1821a5((String) methodD.invoke(null, motionEvent, displayMetrics));
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new zzawe(e);
        }
    }

    public static final void t(List list) throws InterruptedException {
        ExecutorService executorService;
        if (x == null || (executorService = x.b) == null || list.isEmpty()) {
            return;
        }
        try {
            executorService.invokeAll(list, ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.H2)).longValue(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            char[] cArr = AbstractC1865b5.a;
            StringWriter stringWriter = new StringWriter();
            e.printStackTrace(new PrintWriter(stringWriter));
            stringWriter.toString();
        }
    }

    public static O4 u(Context context, com.bumptech.glide.manager.p pVar) {
        synchronized (O4.class) {
            try {
                if (!z) {
                    A = System.currentTimeMillis() / 1000;
                    x = o(context, pVar.a);
                    C2601s7 c2601s7 = AbstractC2773w7.x3;
                    com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                    if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                        B = S4.i(context);
                    }
                    ExecutorService executorService = x.b;
                    if (((Boolean) rVar.c.a(AbstractC2773w7.y3)).booleanValue() && executorService != null) {
                        C = C2039f5.a(context, executorService);
                    }
                    if (((Boolean) rVar.c.a(AbstractC2773w7.M2)).booleanValue()) {
                        D = new J();
                    }
                    if (((Boolean) rVar.c.a(AbstractC2773w7.R2)).booleanValue() || ((Z3) pVar.c).B()) {
                        F = new S4(context, executorService);
                    }
                    if (((Boolean) rVar.c.a(AbstractC2773w7.N2)).booleanValue() || ((Z3) pVar.c).A()) {
                        E = new C2326lq(context, executorService, (Z3) pVar.c, F);
                    }
                    z = true;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return new O4(context, pVar);
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final void a(View view) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.K2)).booleanValue()) {
            if (this.v == null) {
                Z4 z4 = x;
                this.v = new ViewOnAttachStateChangeListenerC1952d5(z4.a, z4.o);
            }
            this.v.a(view);
        }
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String b(Context context) {
        char[] cArr = AbstractC1865b5.a;
        if (Looper.myLooper() != Looper.getMainLooper()) {
            return r(context, null, 1, null, null);
        }
        throw new IllegalStateException("The caller must not be called from the UI thread.");
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final void c(StackTraceElement[] stackTraceElementArr) {
        C2881yn c2881yn;
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U2)).booleanValue() || (c2881yn = this.t) == null) {
            return;
        }
        c2881yn.b = new ArrayList(Arrays.asList(stackTraceElementArr));
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String d(Context context, View view, String str) {
        return r(context, str, 3, view, null);
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String e(Context context) {
        return "19";
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String f(Context context, String str, View view, Activity activity) {
        return r(context, str, 3, view, activity);
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final synchronized void g(int i, int i2, int i3) {
        try {
            if (this.a != null) {
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.E2)).booleanValue()) {
                    p();
                } else {
                    this.a.recycle();
                }
            }
            DisplayMetrics displayMetrics = this.s;
            if (displayMetrics != null) {
                float f = displayMetrics.density;
                this.a = MotionEvent.obtain(0L, i3, 1, i * f, i2 * f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0, 0);
            } else {
                this.a = null;
            }
            this.r = false;
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final synchronized void h(MotionEvent motionEvent) {
        Long l;
        try {
            if (this.q) {
                p();
                this.q = false;
            }
            int action = motionEvent.getAction();
            if (action == 0) {
                this.j = 0.0d;
                this.k = motionEvent.getRawX();
                this.l = motionEvent.getRawY();
            } else if (action == 1 || action == 2) {
                double rawX = motionEvent.getRawX();
                double rawY = motionEvent.getRawY();
                double d = rawX - this.k;
                double d2 = rawY - this.l;
                this.j += Math.sqrt((d2 * d2) + (d * d));
                this.k = rawX;
                this.l = rawY;
            }
            int action2 = motionEvent.getAction();
            if (action2 != 0) {
                try {
                    if (action2 == 1) {
                        MotionEvent motionEventObtain = MotionEvent.obtain(motionEvent);
                        this.a = motionEventObtain;
                        LinkedList linkedList = this.b;
                        linkedList.add(motionEventObtain);
                        if (linkedList.size() > 6) {
                            ((MotionEvent) linkedList.remove()).recycle();
                        }
                        this.e++;
                        this.g = j(new Throwable().getStackTrace());
                    } else if (action2 == 2) {
                        this.d += motionEvent.getHistorySize() + 1;
                        C1821a5 c1821a5N = n(motionEvent);
                        Long l2 = c1821a5N.R;
                        if (l2 != null && c1821a5N.U != null) {
                            this.h = l2.longValue() + c1821a5N.U.longValue() + this.h;
                        }
                        if (this.s != null && (l = c1821a5N.S) != null && c1821a5N.V != null) {
                            this.i = l.longValue() + c1821a5N.V.longValue() + this.i;
                        }
                    } else if (action2 == 3) {
                        this.f++;
                    }
                } catch (zzawe unused) {
                }
            } else {
                this.m = motionEvent.getX();
                this.n = motionEvent.getY();
                this.o = motionEvent.getRawX();
                this.p = motionEvent.getRawY();
                this.c++;
            }
            this.r = true;
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String i(Context context, View view, Activity activity) {
        return r(context, null, 2, view, activity);
    }

    public final long j(StackTraceElement[] stackTraceElementArr) throws zzawe {
        Method methodD = x.d("UtW7g7feJqOHsjIRMP7TbkL8M4VYsmVrsaULCIKJGwvBOELKcxTQZfT6AHg6wl4V", "3s4OpKjyDjUzqtut1o8wCVCKFRdtRePXWRu+sqk/xG8=");
        if (methodD == null || stackTraceElementArr == null) {
            throw new zzawe();
        }
        try {
            return new R4((String) methodD.invoke(null, stackTraceElementArr)).P.longValue();
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new zzawe(e);
        }
    }

    public final C1864b4 k(Context context, View view, Activity activity) throws InterruptedException {
        C2039f5 c2039f5 = C;
        if (c2039f5 != null && c2039f5.d) {
            c2039f5.b = System.currentTimeMillis();
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.M2)).booleanValue()) {
            J j = D;
            j.h = j.g;
            j.g = SystemClock.uptimeMillis();
        }
        C1864b4 c1864b4W = C2384n4.W();
        com.bumptech.glide.manager.p pVar = this.u;
        String str = (String) pVar.b;
        if (!TextUtils.isEmpty(str)) {
            c1864b4W.e();
            C2384n4.v0((C2384n4) c1864b4W.b, str);
        }
        s(o(context, pVar.a), c1864b4W, view, activity, true, context);
        return c1864b4W;
    }

    public final C1864b4 l(Context context) throws InterruptedException {
        long j;
        long j2;
        C2039f5 c2039f5 = C;
        if (c2039f5 != null && c2039f5.d) {
            c2039f5.b = System.currentTimeMillis();
        }
        C2601s7 c2601s7 = AbstractC2773w7.M2;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            J j3 = D;
            j3.b = j3.a;
            j3.a = SystemClock.uptimeMillis();
        }
        C1864b4 c1864b4W = C2384n4.W();
        com.bumptech.glide.manager.p pVar = this.u;
        String str = (String) pVar.b;
        if (!TextUtils.isEmpty(str)) {
            c1864b4W.e();
            C2384n4.v0((C2384n4) c1864b4W.b, str);
        }
        Z4 z4O = o(context, pVar.a);
        if (z4O.b == null) {
            return c1864b4W;
        }
        int iA = z4O.a();
        ArrayList arrayList = new ArrayList();
        if (z4O.n) {
            arrayList.add(new C2171i5(z4O, c1864b4W, iA, context, (Z3) pVar.c, E));
            arrayList.add(new C2256k5(z4O, c1864b4W, A, iA));
            arrayList.add(new C2213j5(z4O, c1864b4W, iA, 2));
            arrayList.add(new C2083g5(z4O, c1864b4W, iA, context));
            arrayList.add(new C2213j5(z4O, c1864b4W, iA, 3));
            arrayList.add(new C2127h5(z4O, c1864b4W, iA, context));
            arrayList.add(new C2213j5(z4O, c1864b4W, iA, 6));
            arrayList.add(new C2213j5(z4O, c1864b4W, iA, 8));
            arrayList.add(new C2213j5(z4O, c1864b4W, iA, 9));
            arrayList.add(new C2213j5(z4O, c1864b4W, iA, 0));
            arrayList.add(new C2213j5(z4O, c1864b4W, iA, 1));
            arrayList.add(new C2213j5(z4O, c1864b4W, iA, 12));
            arrayList.add(new C2213j5(z4O, c1864b4W, iA, 5));
            arrayList.add(new C2213j5(z4O, c1864b4W, iA, 11));
            arrayList.add(new C2428o5(z4O, c1864b4W, iA));
            C2601s7 c2601s72 = AbstractC2773w7.x3;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue()) {
                C2039f5 c2039f52 = C;
                if (c2039f52 != null) {
                    long j4 = c2039f52.d ? c2039f52.b - c2039f52.a : -1L;
                    long j5 = c2039f52.c;
                    c2039f52.c = -1L;
                    j2 = j5;
                    j = j4;
                } else {
                    j = -1;
                    j2 = -1;
                }
                arrayList.add(new C2385n5(z4O, c1864b4W, iA, B, j, j2));
            }
            if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.w3)).booleanValue()) {
                arrayList.add(new C2213j5(z4O, c1864b4W, iA, 10));
            }
            C2213j5 c2213j5 = new C2213j5(z4O, "dRD+JVHrAp9KS52Ek5z+07PqwexnB2SlEw3dstFC/1pUdbIUHq4sOL+yEg/9GhsH", "AVj0chiCvO7NARSM7gnUx+yq9iwGX0sKyhH1s5c2UEE=", c1864b4W, iA, 76);
            c1864b4W = c1864b4W;
            arrayList.add(c2213j5);
            if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.A3)).booleanValue()) {
                arrayList.add(new C2213j5(z4O, c1864b4W, iA, 4));
            }
        } else {
            c1864b4W.e();
            C2384n4.E((C2384n4) c1864b4W.b, 16384L);
        }
        t(arrayList);
        return c1864b4W;
    }

    public final C1864b4 m(Context context, View view, Activity activity) throws IllegalAccessException, InterruptedException, IllegalArgumentException, InvocationTargetException {
        C2039f5 c2039f5 = C;
        if (c2039f5 != null && c2039f5.d) {
            c2039f5.b = System.currentTimeMillis();
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.M2)).booleanValue()) {
            D.b(context, view);
        }
        C1864b4 c1864b4W = C2384n4.W();
        com.bumptech.glide.manager.p pVar = this.u;
        String str = (String) pVar.b;
        c1864b4W.e();
        C2384n4.v0((C2384n4) c1864b4W.b, str);
        s(o(context, pVar.a), c1864b4W, view, activity, false, context);
        return c1864b4W;
    }

    public final C1821a5 n(MotionEvent motionEvent) throws zzawe {
        Method methodD = x.d("MzsWIz4gfLj0a3R+qdHFnq4+xme2LarFguHCIutZgqcm6GnV+OetVQKtggSwCSnr", "3rH82U9H9h0NHlfre8U+glRveAN0QJ52a1RA+MBgcOg=");
        if (methodD == null || motionEvent == null) {
            throw new zzawe();
        }
        try {
            return new C1821a5((String) methodD.invoke(null, motionEvent, this.s));
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new zzawe(e);
        }
    }

    public final void p() {
        this.g = 0L;
        this.c = 0L;
        this.d = 0L;
        this.e = 0L;
        this.f = 0L;
        this.h = 0L;
        this.i = 0L;
        LinkedList linkedList = this.b;
        if (linkedList.isEmpty()) {
            MotionEvent motionEvent = this.a;
            if (motionEvent != null) {
                motionEvent.recycle();
            }
        } else {
            Iterator it2 = linkedList.iterator();
            while (it2.hasNext()) {
                ((MotionEvent) it2.next()).recycle();
            }
            linkedList.clear();
        }
        this.a = null;
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x009d A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String r(android.content.Context r20, java.lang.String r21, int r22, android.view.View r23, android.app.Activity r24) {
        /*
            Method dump skipped, instructions count: 310
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.O4.r(android.content.Context, java.lang.String, int, android.view.View, android.app.Activity):java.lang.String");
    }

    public final void s(Z4 z4, C1864b4 c1864b4, View view, Activity activity, boolean z2, Context context) throws InterruptedException {
        List listAsList;
        Context context2;
        long j;
        long j2;
        MotionEvent motionEvent;
        int i = 1;
        if (z4.n) {
            synchronized (this) {
                try {
                    try {
                        C1821a5 c1821a5Q = q(z4, this.a, this.s);
                        Long l = c1821a5Q.O;
                        if (l != null) {
                            long jLongValue = l.longValue();
                            c1864b4.e();
                            C2384n4.O((C2384n4) c1864b4.b, jLongValue);
                        }
                        Long l2 = c1821a5Q.P;
                        if (l2 != null) {
                            long jLongValue2 = l2.longValue();
                            c1864b4.e();
                            C2384n4.P((C2384n4) c1864b4.b, jLongValue2);
                        }
                        Long l3 = c1821a5Q.Q;
                        if (l3 != null) {
                            long jLongValue3 = l3.longValue();
                            c1864b4.e();
                            C2384n4.M((C2384n4) c1864b4.b, jLongValue3);
                        }
                        if (this.r) {
                            Long l4 = c1821a5Q.R;
                            if (l4 != null) {
                                long jLongValue4 = l4.longValue();
                                c1864b4.e();
                                C2384n4.L((C2384n4) c1864b4.b, jLongValue4);
                            }
                            Long l5 = c1821a5Q.S;
                            if (l5 != null) {
                                long jLongValue5 = l5.longValue();
                                c1864b4.e();
                                C2384n4.I((C2384n4) c1864b4.b, jLongValue5);
                            }
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                } catch (zzawe unused) {
                }
                C2212j4 c2212j4W = C2255k4.w();
                if (this.c > 0) {
                    DisplayMetrics displayMetrics = this.s;
                    char[] cArr = AbstractC1865b5.a;
                    if ((displayMetrics == null || displayMetrics.density == DefinitionKt.NO_Float_VALUE) ? false : true) {
                        long jA = AbstractC1865b5.a(this.j, displayMetrics);
                        c2212j4W.e();
                        C2255k4.A((C2255k4) c2212j4W.b, jA);
                        long jA2 = AbstractC1865b5.a(this.o - this.m, this.s);
                        c2212j4W.e();
                        C2255k4.N((C2255k4) c2212j4W.b, jA2);
                        long jA3 = AbstractC1865b5.a(this.p - this.n, this.s);
                        c2212j4W.e();
                        C2255k4.O((C2255k4) c2212j4W.b, jA3);
                        long jA4 = AbstractC1865b5.a(this.m, this.s);
                        c2212j4W.e();
                        C2255k4.G((C2255k4) c2212j4W.b, jA4);
                        long jA5 = AbstractC1865b5.a(this.n, this.s);
                        c2212j4W.e();
                        C2255k4.I((C2255k4) c2212j4W.b, jA5);
                        if (this.r && (motionEvent = this.a) != null) {
                            long jA6 = AbstractC1865b5.a(((this.m - this.o) + motionEvent.getRawX()) - this.a.getX(), this.s);
                            if (jA6 != 0) {
                                c2212j4W.e();
                                C2255k4.L((C2255k4) c2212j4W.b, jA6);
                            }
                            long jA7 = AbstractC1865b5.a(((this.n - this.p) + this.a.getRawY()) - this.a.getY(), this.s);
                            if (jA7 != 0) {
                                c2212j4W.e();
                                C2255k4.M((C2255k4) c2212j4W.b, jA7);
                            }
                        }
                    }
                }
                try {
                    C1821a5 c1821a5N = n(this.a);
                    Long l6 = c1821a5N.O;
                    if (l6 != null) {
                        long jLongValue6 = l6.longValue();
                        c2212j4W.e();
                        C2255k4.H((C2255k4) c2212j4W.b, jLongValue6);
                    }
                    Long l7 = c1821a5N.P;
                    if (l7 != null) {
                        long jLongValue7 = l7.longValue();
                        c2212j4W.e();
                        C2255k4.J((C2255k4) c2212j4W.b, jLongValue7);
                    }
                    long jLongValue8 = c1821a5N.Q.longValue();
                    c2212j4W.e();
                    C2255k4.F((C2255k4) c2212j4W.b, jLongValue8);
                    if (this.r) {
                        Long l8 = c1821a5N.S;
                        if (l8 != null) {
                            long jLongValue9 = l8.longValue();
                            c2212j4W.e();
                            C2255k4.D((C2255k4) c2212j4W.b, jLongValue9);
                        }
                        Long l9 = c1821a5N.R;
                        if (l9 != null) {
                            long jLongValue10 = l9.longValue();
                            c2212j4W.e();
                            C2255k4.E((C2255k4) c2212j4W.b, jLongValue10);
                        }
                        Long l10 = c1821a5N.T;
                        if (l10 != null) {
                            int i2 = l10.longValue() != 0 ? 2 : 1;
                            c2212j4W.e();
                            C2255k4.Q((C2255k4) c2212j4W.b, i2);
                        }
                        long j3 = this.d;
                        if (j3 > 0) {
                            DisplayMetrics displayMetrics2 = this.s;
                            char[] cArr2 = AbstractC1865b5.a;
                            Long lValueOf = displayMetrics2 != null && (displayMetrics2.density > DefinitionKt.NO_Float_VALUE ? 1 : (displayMetrics2.density == DefinitionKt.NO_Float_VALUE ? 0 : -1)) != 0 ? Long.valueOf(Math.round(this.i / j3)) : null;
                            if (lValueOf != null) {
                                long jLongValue11 = lValueOf.longValue();
                                c2212j4W.e();
                                C2255k4.y((C2255k4) c2212j4W.b, jLongValue11);
                            } else {
                                c2212j4W.e();
                                C2255k4.x((C2255k4) c2212j4W.b);
                            }
                            long jRound = Math.round(this.h / this.d);
                            c2212j4W.e();
                            C2255k4.z((C2255k4) c2212j4W.b, jRound);
                        }
                        Long l11 = c1821a5N.W;
                        if (l11 != null) {
                            long jLongValue12 = l11.longValue();
                            c2212j4W.e();
                            C2255k4.B((C2255k4) c2212j4W.b, jLongValue12);
                        }
                        Long l12 = c1821a5N.X;
                        if (l12 != null) {
                            long jLongValue13 = l12.longValue();
                            c2212j4W.e();
                            C2255k4.K((C2255k4) c2212j4W.b, jLongValue13);
                        }
                        Long l13 = c1821a5N.Y;
                        if (l13 != null) {
                            int i3 = l13.longValue() != 0 ? 2 : 1;
                            c2212j4W.e();
                            C2255k4.P((C2255k4) c2212j4W.b, i3);
                        }
                    }
                } catch (zzawe unused2) {
                }
                long j4 = this.g;
                if (j4 > 0) {
                    c2212j4W.e();
                    C2255k4.C((C2255k4) c2212j4W.b, j4);
                }
                C2255k4 c2255k4 = (C2255k4) c2212j4W.c();
                c1864b4.e();
                C2384n4.S((C2384n4) c1864b4.b, c2255k4);
                long j5 = this.c;
                if (j5 > 0) {
                    c1864b4.e();
                    C2384n4.J((C2384n4) c1864b4.b, j5);
                }
                long j6 = this.d;
                if (j6 > 0) {
                    c1864b4.e();
                    C2384n4.K((C2384n4) c1864b4.b, j6);
                }
                long j7 = this.e;
                if (j7 > 0) {
                    c1864b4.e();
                    C2384n4.N((C2384n4) c1864b4.b, j7);
                }
                long j8 = this.f;
                if (j8 > 0) {
                    c1864b4.e();
                    C2384n4.H((C2384n4) c1864b4.b, j8);
                }
                try {
                    LinkedList linkedList = this.b;
                    int size = linkedList.size() - 1;
                    if (size > 0) {
                        c1864b4.e();
                        C2384n4.p0((C2384n4) c1864b4.b);
                        for (int i4 = 0; i4 < size; i4++) {
                            C1821a5 c1821a5Q2 = q(x, (MotionEvent) linkedList.get(i4), this.s);
                            C2212j4 c2212j4W2 = C2255k4.w();
                            long jLongValue14 = c1821a5Q2.O.longValue();
                            c2212j4W2.e();
                            C2255k4.H((C2255k4) c2212j4W2.b, jLongValue14);
                            long jLongValue15 = c1821a5Q2.P.longValue();
                            c2212j4W2.e();
                            C2255k4.J((C2255k4) c2212j4W2.b, jLongValue15);
                            C2255k4 c2255k42 = (C2255k4) c2212j4W2.c();
                            c1864b4.e();
                            C2384n4.o0((C2384n4) c1864b4.b, c2255k42);
                        }
                    }
                } catch (zzawe unused3) {
                    c1864b4.e();
                    C2384n4.p0((C2384n4) c1864b4.b);
                }
            }
            ArrayList arrayList = new ArrayList();
            if (z4.b != null) {
                int iA = z4.a();
                C2601s7 c2601s7 = AbstractC2773w7.T2;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                    context2 = context;
                    arrayList.add(new C2171i5(z4, c1864b4, iA, context, (Z3) this.u.c, E));
                    arrayList.add(new C2127h5(z4, c1864b4, iA, context2));
                    arrayList.add(new C2083g5(z4, c1864b4, iA, context2));
                    arrayList.add(new C2213j5(z4, c1864b4, iA, 3));
                    C2039f5 c2039f5 = C;
                    if (c2039f5 != null) {
                        long j9 = c2039f5.d ? c2039f5.b - c2039f5.a : -1L;
                        long j10 = c2039f5.c;
                        c2039f5.c = -1L;
                        j2 = j9;
                        j = j10;
                    } else {
                        j = -1;
                        j2 = -1;
                    }
                    arrayList.add(new C2385n5(z4, c1864b4, iA, B, j2, j));
                    arrayList.add(new C2213j5(z4, c1864b4, iA, 10));
                } else {
                    context2 = context;
                }
                arrayList.add(new A4(i, z4, c1864b4));
                arrayList.add(new C2213j5(z4, c1864b4, iA, 2));
                arrayList.add(new C2256k5(z4, c1864b4, A, iA));
                arrayList.add(new C2213j5(z4, c1864b4, iA, 0));
                arrayList.add(new C2213j5(z4, c1864b4, iA, 8));
                arrayList.add(new C2213j5(z4, c1864b4, iA, 9));
                arrayList.add(new C2213j5(z4, c1864b4, iA, 1));
                arrayList.add(new C2213j5(z4, c1864b4, iA, 6));
                arrayList.add(new C2213j5(z4, c1864b4, iA, 12));
                arrayList.add(new C2213j5(z4, c1864b4, iA, 5));
                arrayList.add(new C2213j5(z4, c1864b4, iA, 11));
                arrayList.add(new C2299l5(z4, c1864b4, iA, new Throwable().getStackTrace()));
                arrayList.add(new C2299l5(z4, c1864b4, iA, view));
                arrayList.add(new C2428o5(z4, c1864b4, iA));
                if (((Boolean) rVar.c.a(AbstractC2773w7.I2)).booleanValue()) {
                    arrayList.add(new C2083g5(z4, c1864b4, iA, view, activity));
                }
                if (((Boolean) rVar.c.a(AbstractC2773w7.A3)).booleanValue()) {
                    arrayList.add(new C2213j5(z4, c1864b4, iA, 4));
                }
                if (!z2) {
                    try {
                        if (((Boolean) rVar.c.a(AbstractC2773w7.L2)).booleanValue()) {
                            arrayList.add(new C2342m5(z4, c1864b4, iA, this.w, view, context2));
                        }
                    } catch (IllegalStateException unused4) {
                    }
                    try {
                        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.M2)).booleanValue()) {
                            arrayList.add(new C2299l5(z4, c1864b4, iA, D));
                        }
                    } catch (IllegalStateException unused5) {
                    }
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U2)).booleanValue()) {
                        arrayList.add(new C2299l5(z4, c1864b4, iA, this.t));
                    }
                } else if (((Boolean) rVar.c.a(AbstractC2773w7.K2)).booleanValue()) {
                    arrayList.add(new C2471p5(z4, c1864b4, iA, this.v));
                }
            }
            listAsList = arrayList;
        } else {
            c1864b4.e();
            C2384n4.E((C2384n4) c1864b4.b, 16384L);
            listAsList = Arrays.asList(new A4(i, z4, c1864b4));
        }
        t(listAsList);
    }
}
