package com.amazon.aps.ads.privacy;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.Bo;
import com.google.android.gms.internal.ads.C1847ao;
import com.google.android.gms.internal.ads.C2367mo;
import com.google.android.gms.internal.ads.C2407nl;
import com.google.android.gms.internal.ads.Gk;
import com.google.android.gms.internal.ads.InterfaceC1844al;
import com.google.android.gms.internal.ads.Pk;
import java.io.Serializable;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArraySet;

/* loaded from: classes.dex */
public final class a {
    public static int j;
    public boolean a;
    public boolean b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;
    public Serializable g;
    public Object h;
    public Object i;

    public a(Looper looper, C1847ao c1847ao, InterfaceC1844al interfaceC1844al) {
        this(new CopyOnWriteArraySet(), looper, c1847ao, interfaceC1844al, true);
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x0173 A[Catch: Exception -> 0x01ee, TryCatch #2 {Exception -> 0x01ee, blocks: (B:88:0x0145, B:92:0x0156, B:94:0x015d, B:98:0x0168, B:100:0x0173, B:102:0x0179, B:106:0x0182, B:110:0x01a0, B:112:0x01ab, B:115:0x01b4), top: B:119:0x0145 }] */
    /* JADX WARN: Removed duplicated region for block: B:105:0x0181  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x019d  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x019f  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x01ab A[Catch: Exception -> 0x01ee, TryCatch #2 {Exception -> 0x01ee, blocks: (B:88:0x0145, B:92:0x0156, B:94:0x015d, B:98:0x0168, B:100:0x0173, B:102:0x0179, B:106:0x0182, B:110:0x01a0, B:112:0x01ab, B:115:0x01b4), top: B:119:0x0145 }] */
    /* JADX WARN: Removed duplicated region for block: B:28:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0142  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0153  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x0155  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x015d A[Catch: Exception -> 0x01ee, TryCatch #2 {Exception -> 0x01ee, blocks: (B:88:0x0145, B:92:0x0156, B:94:0x015d, B:98:0x0168, B:100:0x0173, B:102:0x0179, B:106:0x0182, B:110:0x01a0, B:112:0x01ab, B:115:0x01b4), top: B:119:0x0145 }] */
    /* JADX WARN: Removed duplicated region for block: B:97:0x0167  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void a(java.lang.String r9) {
        /*
            Method dump skipped, instructions count: 502
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.amazon.aps.ads.privacy.a.a(java.lang.String):void");
    }

    public void b(Object obj) {
        synchronized (this.i) {
            try {
                if (this.a) {
                    return;
                }
                ((CopyOnWriteArraySet) this.f).add(new C2407nl(obj));
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void c() {
        f();
        ArrayDeque arrayDeque = (ArrayDeque) this.h;
        if (arrayDeque.isEmpty()) {
            return;
        }
        Bo bo = (Bo) this.d;
        if (!bo.a.hasMessages(1)) {
            C2367mo c2367moE = Bo.e();
            Handler handler = bo.a;
            Message messageObtainMessage = handler.obtainMessage(1);
            c2367moE.a = messageObtainMessage;
            messageObtainMessage.getClass();
            handler.sendMessageAtFrontOfQueue(messageObtainMessage);
            c2367moE.a = null;
            Bo.d(c2367moE);
        }
        ArrayDeque arrayDeque2 = (ArrayDeque) this.g;
        boolean zIsEmpty = arrayDeque2.isEmpty();
        arrayDeque2.addAll(arrayDeque);
        arrayDeque.clear();
        if (zIsEmpty) {
            while (!arrayDeque2.isEmpty()) {
                ((Runnable) arrayDeque2.peekFirst()).run();
                arrayDeque2.removeFirst();
            }
        }
    }

    public void d(int i, Pk pk) {
        f();
        ((ArrayDeque) this.h).add(new Gk(new CopyOnWriteArraySet((CopyOnWriteArraySet) this.f), i, pk, 0));
    }

    public void e() {
        f();
        synchronized (this.i) {
            this.a = true;
        }
        CopyOnWriteArraySet copyOnWriteArraySet = (CopyOnWriteArraySet) this.f;
        Iterator it2 = copyOnWriteArraySet.iterator();
        while (it2.hasNext()) {
            C2407nl c2407nl = (C2407nl) it2.next();
            InterfaceC1844al interfaceC1844al = (InterfaceC1844al) this.e;
            c2407nl.d = true;
            if (c2407nl.c) {
                c2407nl.c = false;
                interfaceC1844al.c(c2407nl.a, c2407nl.b.N());
            }
        }
        copyOnWriteArraySet.clear();
    }

    public void f() {
        if (this.b) {
            AbstractC1795We.L(Thread.currentThread() == ((Bo) this.d).a.getLooper().getThread());
        }
    }

    public a(CopyOnWriteArraySet copyOnWriteArraySet, Looper looper, C1847ao c1847ao, InterfaceC1844al interfaceC1844al, boolean z) {
        this.c = c1847ao;
        this.f = copyOnWriteArraySet;
        this.e = interfaceC1844al;
        this.i = new Object();
        this.g = new ArrayDeque();
        this.h = new ArrayDeque();
        this.d = c1847ao.a(looper, new Handler.Callback() { // from class: com.google.android.gms.internal.ads.xk
            @Override // android.os.Handler.Callback
            public final boolean handleMessage(Message message) {
                com.amazon.aps.ads.privacy.a aVar = this.a;
                Iterator it2 = ((CopyOnWriteArraySet) aVar.f).iterator();
                while (it2.hasNext()) {
                    C2407nl c2407nl = (C2407nl) it2.next();
                    if (!c2407nl.d && c2407nl.c) {
                        C2049fF c2049fFN = c2407nl.b.N();
                        c2407nl.b = new androidx.appcompat.app.K(10);
                        c2407nl.c = false;
                        ((InterfaceC1844al) aVar.e).c(c2407nl.a, c2049fFN);
                    }
                    if (((Bo) aVar.d).a.hasMessages(1)) {
                        break;
                    }
                }
                return true;
            }
        });
        this.b = z;
    }
}
