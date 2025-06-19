package com.google.android.gms.common.api.internal;

import android.content.Context;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import android.util.SparseIntArray;
import androidx.appcompat.app.J;
import androidx.camera.camera2.internal.c0;
import androidx.camera.camera2.internal.p0;
import androidx.collection.C0208f;
import androidx.collection.C0209g;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.AbstractC1655e;
import com.google.android.gms.internal.ads.Ls;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class n implements com.google.android.gms.common.api.f, com.google.android.gms.common.api.g {
    public final com.google.android.gms.common.api.c b;
    public final C1643a c;
    public final com.quizlet.data.repository.explanations.myexplanations.a d;
    public final int g;
    public final x h;
    public boolean i;
    public final /* synthetic */ C1647e m;
    public final LinkedList a = new LinkedList();
    public final HashSet e = new HashSet();
    public final HashMap f = new HashMap();
    public final ArrayList j = new ArrayList();
    public ConnectionResult k = null;
    public int l = 0;

    /* JADX WARN: Multi-variable type inference failed */
    public n(C1647e c1647e, com.google.android.gms.common.api.e eVar) {
        this.m = c1647e;
        Looper looper = c1647e.n.getLooper();
        com.quizlet.data.repository.folderwithcreator.e eVarA = eVar.a();
        C0209g c0209g = (C0209g) eVarA.b;
        String str = (String) eVarA.c;
        String str2 = (String) eVarA.d;
        com.google.android.gms.signin.a aVar = com.google.android.gms.signin.a.a;
        c0 c0Var = new c0(c0209g, (C0208f) null, str, str2, aVar);
        com.google.android.gms.auth.api.b bVar = (com.google.android.gms.auth.api.b) eVar.d.b;
        com.google.android.gms.common.internal.u.h(bVar);
        com.google.android.gms.common.api.c cVarC = bVar.c(eVar.a, looper, c0Var, eVar.e, this, this);
        com.google.firebase.platforminfo.c cVar = eVar.c;
        if (cVar == null || !(cVarC instanceof AbstractC1655e)) {
            String str3 = eVar.b;
            if (str3 != null && (cVarC instanceof AbstractC1655e)) {
                ((AbstractC1655e) cVarC).s = str3;
            }
        } else {
            ((AbstractC1655e) cVarC).t = cVar;
        }
        this.b = cVarC;
        this.c = eVar.f;
        this.d = new com.quizlet.data.repository.explanations.myexplanations.a(9);
        this.g = eVar.h;
        if (!cVarC.b()) {
            this.h = null;
            return;
        }
        Context context = c1647e.e;
        Ls ls = c1647e.n;
        com.quizlet.data.repository.folderwithcreator.e eVarA2 = eVar.a();
        this.h = new x(context, ls, new c0((C0209g) eVarA2.b, (C0208f) null, (String) eVarA2.c, (String) eVarA2.d, aVar));
    }

    @Override // com.google.android.gms.common.api.f
    public final void V(int i) {
        C1647e c1647e = this.m;
        if (Looper.myLooper() == c1647e.n.getLooper()) {
            b(i);
        } else {
            c1647e.n.post(new androidx.core.provider.a(this, i, 3));
        }
    }

    @Override // com.google.android.gms.common.api.f
    public final void X() {
        C1647e c1647e = this.m;
        if (Looper.myLooper() == c1647e.n.getLooper()) {
            a();
        } else {
            c1647e.n.post(new J(this, 28));
        }
    }

    public final void a() {
        C1647e c1647e = this.m;
        com.google.android.gms.common.internal.u.c(c1647e.n);
        this.k = null;
        i(ConnectionResult.e);
        if (this.i) {
            Ls ls = c1647e.n;
            C1643a c1643a = this.c;
            ls.removeMessages(11, c1643a);
            c1647e.n.removeMessages(9, c1643a);
            this.i = false;
        }
        Iterator it2 = this.f.values().iterator();
        if (it2.hasNext()) {
            throw null;
        }
        d();
        h();
    }

    public final void b(int i) {
        com.google.android.gms.common.internal.u.c(this.m.n);
        this.k = null;
        this.i = true;
        String str = ((AbstractC1655e) this.b).a;
        com.quizlet.data.repository.explanations.myexplanations.a aVar = this.d;
        aVar.getClass();
        StringBuilder sb = new StringBuilder("The connection to Google Play services was lost");
        if (i == 1) {
            sb.append(" due to service disconnection.");
        } else if (i == 3) {
            sb.append(" due to dead object exception.");
        }
        if (str != null) {
            sb.append(" Last reason for disconnect: ");
            sb.append(str);
        }
        aVar.m(true, new Status(20, sb.toString(), null, null));
        C1643a c1643a = this.c;
        C1647e c1647e = this.m;
        Ls ls = c1647e.n;
        ls.sendMessageDelayed(Message.obtain(ls, 9, c1643a), 5000L);
        Ls ls2 = c1647e.n;
        ls2.sendMessageDelayed(Message.obtain(ls2, 11, c1643a), 120000L);
        SparseIntArray sparseIntArray = (SparseIntArray) c1647e.g.b;
        synchronized (sparseIntArray) {
            sparseIntArray.clear();
        }
        Iterator it2 = this.f.values().iterator();
        while (it2.hasNext()) {
            ((v) it2.next()).getClass();
        }
    }

    public final boolean c(ConnectionResult connectionResult) {
        synchronized (C1647e.r) {
            try {
                C1647e c1647e = this.m;
                if (c1647e.k == null || !c1647e.l.contains(this.c)) {
                    return false;
                }
                l lVar = c1647e.k;
                int i = this.g;
                lVar.getClass();
                D d = new D(connectionResult, i);
                AtomicReference atomicReference = lVar.c;
                while (true) {
                    if (atomicReference.compareAndSet(null, d)) {
                        lVar.d.post(new com.google.common.util.concurrent.d(lVar, false, d, 22));
                        break;
                    }
                    if (atomicReference.get() != null) {
                        break;
                    }
                }
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void d() {
        LinkedList linkedList = this.a;
        ArrayList arrayList = new ArrayList(linkedList);
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            C c = (C) arrayList.get(i);
            if (!((AbstractC1655e) this.b).q()) {
                return;
            }
            if (e(c)) {
                linkedList.remove(c);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:33:0x007e  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0096  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean e(com.google.android.gms.common.api.internal.C r15) throws android.content.res.Resources.NotFoundException {
        /*
            Method dump skipped, instructions count: 332
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.api.internal.n.e(com.google.android.gms.common.api.internal.C):boolean");
    }

    public final void f(Status status, RuntimeException runtimeException, boolean z) {
        com.google.android.gms.common.internal.u.c(this.m.n);
        if ((status == null) == (runtimeException == null)) {
            throw new IllegalArgumentException("Status XOR exception should be null");
        }
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            C c = (C) it2.next();
            if (!z || c.a == 2) {
                if (status != null) {
                    c.a(status);
                } else {
                    c.b(runtimeException);
                }
                it2.remove();
            }
        }
    }

    @Override // com.google.android.gms.common.api.g
    public final void f0(ConnectionResult connectionResult) {
        k(connectionResult, null);
    }

    public final void g(Status status) {
        com.google.android.gms.common.internal.u.c(this.m.n);
        f(status, null, false);
    }

    public final void h() {
        C1647e c1647e = this.m;
        Ls ls = c1647e.n;
        C1643a c1643a = this.c;
        ls.removeMessages(12, c1643a);
        Ls ls2 = c1647e.n;
        ls2.sendMessageDelayed(ls2.obtainMessage(12, c1643a), c1647e.a);
    }

    public final void i(ConnectionResult connectionResult) {
        HashSet hashSet = this.e;
        Iterator it2 = hashSet.iterator();
        if (!it2.hasNext()) {
            hashSet.clear();
            return;
        }
        if (it2.next() != null) {
            throw new ClassCastException();
        }
        if (com.google.android.gms.common.internal.u.l(connectionResult, ConnectionResult.e)) {
            AbstractC1655e abstractC1655e = (AbstractC1655e) this.b;
            if (!abstractC1655e.q() || abstractC1655e.b == null) {
                throw new RuntimeException("Failed to connect when checking package");
            }
        }
        throw null;
    }

    public final void j(ConnectionResult connectionResult) {
        com.google.android.gms.common.internal.u.c(this.m.n);
        Object obj = this.b;
        String name = obj.getClass().getName();
        String strValueOf = String.valueOf(connectionResult);
        AbstractC1655e abstractC1655e = (AbstractC1655e) obj;
        abstractC1655e.f(androidx.compose.ui.node.B.j(new StringBuilder(name.length() + 25 + strValueOf.length()), "onSignInFailed for ", name, " with ", strValueOf));
        k(connectionResult, null);
    }

    public final void k(ConnectionResult connectionResult, RuntimeException runtimeException) {
        com.google.android.gms.signin.internal.a aVar;
        C1647e c1647e = this.m;
        com.google.android.gms.common.internal.u.c(c1647e.n);
        x xVar = this.h;
        if (xVar != null && (aVar = xVar.g) != null) {
            aVar.e();
        }
        com.google.android.gms.common.internal.u.c(this.m.n);
        this.k = null;
        SparseIntArray sparseIntArray = (SparseIntArray) c1647e.g.b;
        synchronized (sparseIntArray) {
            sparseIntArray.clear();
        }
        i(connectionResult);
        if ((this.b instanceof com.google.android.gms.common.internal.service.c) && connectionResult.b != 24) {
            c1647e.b = true;
            Ls ls = c1647e.n;
            ls.sendMessageDelayed(ls.obtainMessage(19), 300000L);
        }
        int i = connectionResult.b;
        if (i == 4) {
            g(C1647e.q);
            return;
        }
        if (i == 25) {
            g(C1647e.c(this.c, connectionResult));
            return;
        }
        LinkedList linkedList = this.a;
        if (linkedList.isEmpty()) {
            this.k = connectionResult;
            return;
        }
        if (runtimeException != null) {
            com.google.android.gms.common.internal.u.c(c1647e.n);
            f(null, runtimeException, false);
            return;
        }
        if (!c1647e.o) {
            g(C1647e.c(this.c, connectionResult));
            return;
        }
        C1643a c1643a = this.c;
        f(C1647e.c(c1643a, connectionResult), null, true);
        if (linkedList.isEmpty() || c(connectionResult) || c1647e.g(connectionResult, this.g)) {
            return;
        }
        if (connectionResult.b == 18) {
            this.i = true;
        }
        if (!this.i) {
            g(C1647e.c(c1643a, connectionResult));
        } else {
            Ls ls2 = c1647e.n;
            ls2.sendMessageDelayed(Message.obtain(ls2, 9, c1643a), 5000L);
        }
    }

    public final void l(C c) {
        com.google.android.gms.common.internal.u.c(this.m.n);
        boolean zQ = ((AbstractC1655e) this.b).q();
        LinkedList linkedList = this.a;
        if (zQ) {
            if (e(c)) {
                h();
                return;
            } else {
                linkedList.add(c);
                return;
            }
        }
        linkedList.add(c);
        ConnectionResult connectionResult = this.k;
        if (connectionResult == null || connectionResult.b == 0 || connectionResult.c == null) {
            n();
        } else {
            k(connectionResult, null);
        }
    }

    public final void m() {
        C1647e c1647e = this.m;
        com.google.android.gms.common.internal.u.c(c1647e.n);
        Status status = C1647e.p;
        g(status);
        this.d.m(false, status);
        for (AbstractC1650h abstractC1650h : (AbstractC1650h[]) this.f.keySet().toArray(new AbstractC1650h[0])) {
            l(new B(abstractC1650h, new com.google.android.gms.tasks.f()));
        }
        i(new ConnectionResult(4));
        if (((AbstractC1655e) this.b).q()) {
            c1647e.n.post(new J(new com.airbnb.lottie.network.c(this, 20), 29));
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void n() {
        C1647e c1647e = this.m;
        com.google.android.gms.common.internal.u.c(c1647e.n);
        com.google.android.gms.common.api.c cVar = this.b;
        AbstractC1655e abstractC1655e = (AbstractC1655e) cVar;
        if (abstractC1655e.q() || abstractC1655e.r()) {
            return;
        }
        try {
            int iA = c1647e.g.A(c1647e.e, cVar);
            if (iA != 0) {
                ConnectionResult connectionResult = new ConnectionResult(iA, null);
                String name = cVar.getClass().getName();
                String string = connectionResult.toString();
                StringBuilder sb = new StringBuilder(name.length() + 35 + string.length());
                sb.append("The service for ");
                sb.append(name);
                sb.append(" is not available: ");
                sb.append(string);
                Log.w("GoogleApiManager", sb.toString());
                k(connectionResult, null);
                return;
            }
            C1643a c1643a = this.c;
            p0 p0Var = new p0();
            p0Var.f = c1647e;
            p0Var.a = null;
            p0Var.e = null;
            p0Var.b = false;
            p0Var.c = cVar;
            p0Var.d = c1643a;
            if (cVar.b()) {
                x xVar = this.h;
                com.google.android.gms.common.internal.u.h(xVar);
                com.google.android.gms.signin.internal.a aVar = xVar.g;
                if (aVar != null) {
                    aVar.e();
                }
                Integer numValueOf = Integer.valueOf(System.identityHashCode(xVar));
                c0 c0Var = xVar.f;
                c0Var.g = numValueOf;
                Ls ls = xVar.c;
                Looper looper = ls.getLooper();
                xVar.g = (com.google.android.gms.signin.internal.a) xVar.d.c(xVar.b, looper, c0Var, (com.google.android.gms.signin.a) c0Var.f, xVar, xVar);
                xVar.h = p0Var;
                Set set = xVar.e;
                if (set == null || set.isEmpty()) {
                    ls.post(new w(xVar, 0));
                } else {
                    com.google.android.gms.signin.internal.a aVar2 = xVar.g;
                    aVar2.getClass();
                    aVar2.j = new com.google.android.gms.common.internal.i(aVar2);
                    aVar2.w(2, null);
                }
            }
            try {
                abstractC1655e.j = p0Var;
                abstractC1655e.w(2, null);
            } catch (SecurityException e) {
                k(new ConnectionResult(10), e);
            }
        } catch (IllegalStateException e2) {
            k(new ConnectionResult(10), e2);
        }
    }
}
