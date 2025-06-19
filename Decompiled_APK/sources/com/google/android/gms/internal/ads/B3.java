package com.google.android.gms.internal.ads;

import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import androidx.compose.material3.C0676l1;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public abstract class B3 implements Comparable {
    public final G3 a;
    public final int b;
    public final String c;
    public final int d;
    public final Object e;
    public final D3 f;
    public Integer g;
    public C3 h;
    public boolean i;
    public C2683u3 j;
    public com.quizlet.data.repository.explanations.textbook.a k;
    public final C0676l1 l;

    public B3(int i, String str, D3 d3) {
        Uri uri;
        String host;
        this.a = G3.c ? new G3() : null;
        this.e = new Object();
        int iHashCode = 0;
        this.i = false;
        this.j = null;
        this.b = i;
        this.c = str;
        this.f = d3;
        C0676l1 c0676l1 = new C0676l1();
        c0676l1.a = 2500;
        this.l = c0676l1;
        if (!TextUtils.isEmpty(str) && (uri = Uri.parse(str)) != null && (host = uri.getHost()) != null) {
            iHashCode = host.hashCode();
        }
        this.d = iHashCode;
    }

    public abstract androidx.browser.customtabs.k a(A3 a3);

    public final String b() {
        int i = this.b;
        String str = this.c;
        return i != 0 ? android.support.v4.media.session.a.l(Integer.toString(1), "-", str) : str;
    }

    public Map c() {
        return Collections.EMPTY_MAP;
    }

    @Override // java.lang.Comparable
    public final /* bridge */ /* synthetic */ int compareTo(Object obj) {
        return this.g.intValue() - ((B3) obj).g.intValue();
    }

    public final void d(String str) {
        if (G3.c) {
            this.a.a(Thread.currentThread().getId(), str);
        }
    }

    public abstract void e(Object obj);

    public final void f(String str) {
        C3 c3 = this.h;
        if (c3 != null) {
            HashSet hashSet = (HashSet) c3.b;
            synchronized (hashSet) {
                hashSet.remove(this);
            }
            ArrayList arrayList = (ArrayList) c3.i;
            synchronized (arrayList) {
                Iterator it2 = arrayList.iterator();
                if (it2.hasNext()) {
                    if (it2.next() != null) {
                        throw new ClassCastException();
                    }
                    throw null;
                }
            }
            c3.f();
        }
        if (G3.c) {
            long id = Thread.currentThread().getId();
            if (Looper.myLooper() != Looper.getMainLooper()) {
                new Handler(Looper.getMainLooper()).post(new com.android.volley.i(this, str, id, 2));
                return;
            }
            G3 g3 = this.a;
            g3.a(id, str);
            g3.b(toString());
        }
    }

    public final void g() {
        com.quizlet.data.repository.explanations.textbook.a aVar;
        synchronized (this.e) {
            aVar = this.k;
        }
        if (aVar != null) {
            aVar.h(this);
        }
    }

    public final void h(androidx.browser.customtabs.k kVar) {
        com.quizlet.data.repository.explanations.textbook.a aVar;
        List list;
        synchronized (this.e) {
            aVar = this.k;
        }
        if (aVar != null) {
            C2683u3 c2683u3 = (C2683u3) kVar.c;
            if (c2683u3 != null) {
                if (c2683u3.e >= System.currentTimeMillis()) {
                    String strB = b();
                    synchronized (aVar) {
                        list = (List) ((HashMap) aVar.a).remove(strB);
                    }
                    if (list != null) {
                        if (H3.a) {
                            H3.b("Releasing %d waiting requests for cacheKey=%s.", Integer.valueOf(list.size()), strB);
                        }
                        Iterator it2 = list.iterator();
                        while (it2.hasNext()) {
                            ((S4) aVar.d).g((B3) it2.next(), kVar, null);
                        }
                        return;
                    }
                    return;
                }
            }
            aVar.h(this);
        }
    }

    public final void i() {
        C3 c3 = this.h;
        if (c3 != null) {
            c3.f();
        }
    }

    public final boolean j() {
        boolean z;
        synchronized (this.e) {
            z = this.i;
        }
        return z;
    }

    public byte[] k() {
        return null;
    }

    public final String toString() {
        String strValueOf = String.valueOf(Integer.toHexString(this.d));
        synchronized (this.e) {
        }
        return "[ ] " + this.c + " " + "0x".concat(strValueOf) + " NORMAL " + this.g;
    }
}
