package com.google.firebase.sessions;

import android.os.Bundle;
import android.os.DeadObjectException;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3555w4;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c0 extends Handler {
    public boolean a;
    public long b;
    public final ArrayList c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c0(Looper looper) {
        super(looper);
        Intrinsics.checkNotNullParameter(looper, "looper");
        this.c = new ArrayList();
    }

    public final void a() throws RemoteException {
        Q q = (Q) ((C3987i) ((InterfaceC3996s) AbstractC3555w4.d().b(InterfaceC3996s.class))).k.get();
        N sessionDetails = ((W) ((C3987i) ((InterfaceC3996s) AbstractC3555w4.d().b(InterfaceC3996s.class))).m.get()).e;
        if (sessionDetails == null) {
            Intrinsics.m("currentSession");
            throw null;
        }
        U u = (U) q;
        u.getClass();
        Intrinsics.checkNotNullParameter(sessionDetails, "sessionDetails");
        kotlinx.coroutines.E.A(kotlinx.coroutines.E.c(u.e), null, null, new S(u, sessionDetails, null), 3);
        Iterator it2 = new ArrayList(this.c).iterator();
        while (it2.hasNext()) {
            Messenger it3 = (Messenger) it2.next();
            Intrinsics.checkNotNullExpressionValue(it3, "it");
            b(it3);
        }
    }

    public final void b(Messenger messenger) throws RemoteException {
        try {
            if (this.a) {
                N n = ((W) ((C3987i) ((InterfaceC3996s) AbstractC3555w4.d().b(InterfaceC3996s.class))).m.get()).e;
                if (n != null) {
                    d(messenger, n.a);
                    return;
                } else {
                    Intrinsics.m("currentSession");
                    throw null;
                }
            }
            C3999v c3999v = (C3999v) ((L) ((C3987i) ((InterfaceC3996s) AbstractC3555w4.d().b(InterfaceC3996s.class))).j.get()).c.get();
            String str = c3999v != null ? c3999v.a : null;
            if (str != null) {
                d(messenger, str);
            }
        } catch (IllegalStateException e) {
            Log.w("SessionLifecycleService", "Failed to send session to client.", e);
        }
    }

    public final void c() throws RemoteException {
        try {
            W w = (W) ((C3987i) ((InterfaceC3996s) AbstractC3555w4.d().b(InterfaceC3996s.class))).m.get();
            int i = w.d + 1;
            w.d = i;
            String strA = i == 0 ? w.c : w.a();
            int i2 = w.d;
            w.a.getClass();
            w.e = new N(i2, System.currentTimeMillis() * 1000, strA, w.c);
            a();
            L l = (L) ((C3987i) ((InterfaceC3996s) AbstractC3555w4.d().b(InterfaceC3996s.class))).j.get();
            N n = ((W) ((C3987i) ((InterfaceC3996s) AbstractC3555w4.d().b(InterfaceC3996s.class))).m.get()).e;
            if (n == null) {
                Intrinsics.m("currentSession");
                throw null;
            }
            String sessionId = n.a;
            l.getClass();
            Intrinsics.checkNotNullParameter(sessionId, "sessionId");
            kotlinx.coroutines.E.A(kotlinx.coroutines.E.c(l.a), null, null, new K(l, sessionId, null), 3);
        } catch (IllegalStateException e) {
            Log.w("SessionLifecycleService", "Failed to generate new session.", e);
        }
    }

    public final void d(Messenger messenger, String str) throws RemoteException {
        try {
            Bundle bundle = new Bundle();
            bundle.putString("SessionUpdateExtra", str);
            Message messageObtain = Message.obtain(null, 3, 0, 0);
            messageObtain.setData(bundle);
            messenger.send(messageObtain);
        } catch (DeadObjectException unused) {
            Objects.toString(messenger);
            this.c.remove(messenger);
        } catch (Exception e) {
            Log.w("SessionLifecycleService", "Unable to push new session to " + messenger + '.', e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00b6  */
    @Override // android.os.Handler
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void handleMessage(android.os.Message r9) throws android.os.RemoteException {
        /*
            r8 = this;
            java.lang.String r0 = "msg"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            long r0 = r8.b
            long r2 = r9.getWhen()
            int r0 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r0 <= 0) goto L13
            r9.getWhen()
            return
        L13:
            int r0 = r9.what
            r1 = 1
            if (r0 == r1) goto L5c
            r1 = 2
            if (r0 == r1) goto L52
            r1 = 4
            if (r0 == r1) goto L35
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r1 = "Received unexpected event from the SessionLifecycleClient: "
            r0.<init>(r1)
            r0.append(r9)
            java.lang.String r0 = r0.toString()
            java.lang.String r1 = "SessionLifecycleService"
            android.util.Log.w(r1, r0)
            super.handleMessage(r9)
            return
        L35:
            java.util.ArrayList r0 = r8.c
            android.os.Messenger r1 = r9.replyTo
            r0.add(r1)
            android.os.Messenger r1 = r9.replyTo
            java.lang.String r2 = "msg.replyTo"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)
            r8.b(r1)
            android.os.Messenger r1 = r9.replyTo
            java.util.Objects.toString(r1)
            r9.getWhen()
            r0.size()
            return
        L52:
            r9.getWhen()
            long r0 = r9.getWhen()
            r8.b = r0
            return
        L5c:
            r9.getWhen()
            boolean r0 = r8.a
            if (r0 != 0) goto L69
            r8.a = r1
            r8.c()
            goto Lcb
        L69:
            long r0 = r9.getWhen()
            long r2 = r8.b
            long r0 = r0 - r2
            com.google.firebase.h r2 = com.google.android.gms.internal.mlkit_vision_common.AbstractC3555w4.d()
            java.lang.Class<com.google.firebase.sessions.s> r3 = com.google.firebase.sessions.InterfaceC3996s.class
            java.lang.Object r2 = r2.b(r3)
            com.google.firebase.sessions.s r2 = (com.google.firebase.sessions.InterfaceC3996s) r2
            com.google.firebase.sessions.i r2 = (com.google.firebase.sessions.C3987i) r2
            javax.inject.a r2 = r2.h
            java.lang.Object r2 = r2.get()
            com.google.firebase.sessions.settings.j r2 = (com.google.firebase.sessions.settings.j) r2
            com.google.firebase.sessions.settings.o r3 = r2.a
            kotlin.time.b r3 = r3.b()
            r4 = 0
            if (r3 == 0) goto L9f
            kotlin.time.a r6 = kotlin.time.b.b
            long r6 = r3.a
            int r3 = (r6 > r4 ? 1 : (r6 == r4 ? 0 : -1))
            if (r3 <= 0) goto L9f
            boolean r3 = kotlin.time.b.g(r6)
            if (r3 != 0) goto L9f
            goto Lc0
        L9f:
            com.google.firebase.sessions.settings.o r2 = r2.b
            kotlin.time.b r2 = r2.b()
            if (r2 == 0) goto Lb6
            kotlin.time.a r3 = kotlin.time.b.b
            long r6 = r2.a
            int r2 = (r6 > r4 ? 1 : (r6 == r4 ? 0 : -1))
            if (r2 <= 0) goto Lb6
            boolean r2 = kotlin.time.b.g(r6)
            if (r2 != 0) goto Lb6
            goto Lc0
        Lb6:
            kotlin.time.a r2 = kotlin.time.b.b
            r2 = 30
            kotlin.time.d r3 = kotlin.time.d.e
            long r6 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3397u1.f(r2, r3)
        Lc0:
            long r2 = kotlin.time.b.e(r6)
            int r0 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r0 <= 0) goto Lcb
            r8.c()
        Lcb:
            long r0 = r9.getWhen()
            r8.b = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.sessions.c0.handleMessage(android.os.Message):void");
    }
}
