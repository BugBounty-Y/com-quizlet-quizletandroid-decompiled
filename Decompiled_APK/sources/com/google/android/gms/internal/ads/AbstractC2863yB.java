package com.google.android.gms.internal.ads;

import android.view.View;
import java.lang.ref.WeakReference;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.ads.yB, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2863yB {
    public static MessageDigest b;
    public final Object a;

    public AbstractC2863yB(int i) {
        switch (i) {
            case 5:
                this.a = new C2518q9();
                break;
            default:
                this.a = new Object();
                break;
        }
    }

    public abstract void G();

    public abstract byte U0(long j);

    public MessageDigest V0() {
        synchronized (this.a) {
            MessageDigest messageDigest = b;
            if (messageDigest != null) {
                return messageDigest;
            }
            for (int i = 0; i < 2; i++) {
                try {
                    b = MessageDigest.getInstance("MD5");
                } catch (NoSuchAlgorithmException unused) {
                }
            }
            return b;
        }
    }

    public abstract double W0(long j, Object obj);

    public abstract void X0(int i, long j);

    public abstract float Y0(long j, Object obj);

    public abstract void Z0(long j, byte[] bArr, long j2, long j3);

    public abstract int a1();

    public abstract void b1(Object obj, long j, boolean z);

    public abstract void c1(Object obj, long j, byte b2);

    public abstract void d1(Object obj, long j, double d);

    public abstract void e1(Object obj, long j, float f);

    public abstract void f1();

    public abstract boolean g1(long j, Object obj);

    public abstract A9 h1();

    public synchronized void i1(Object obj, Executor executor) {
        ((HashMap) this.a).put(obj, executor);
    }

    public synchronized void j1(Xh xh) {
        for (Map.Entry entry : ((HashMap) this.a).entrySet()) {
            ((Executor) entry.getValue()).execute(new Qv(22, xh, entry.getKey()));
        }
    }

    public AbstractC2863yB(View view) {
        this.a = new WeakReference(view);
    }

    public AbstractC2863yB(Set set) {
        this.a = new HashMap();
        synchronized (this) {
            Iterator it2 = set.iterator();
            while (it2.hasNext()) {
                C2318li c2318li = (C2318li) it2.next();
                synchronized (this) {
                    i1(c2318li.a, c2318li.b);
                }
            }
        }
    }
}
