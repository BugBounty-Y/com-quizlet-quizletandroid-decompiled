package okhttp3.internal.concurrent;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3363l2;
import java.util.ArrayList;
import java.util.concurrent.RejectedExecutionException;
import java.util.logging.Level;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final d a;
    public final String b;
    public boolean c;
    public a d;
    public final ArrayList e;
    public boolean f;

    public c(d taskRunner, String name) {
        Intrinsics.checkNotNullParameter(taskRunner, "taskRunner");
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = taskRunner;
        this.b = name;
        this.e = new ArrayList();
    }

    public final void a() {
        byte[] bArr = okhttp3.internal.b.a;
        synchronized (this.a) {
            try {
                if (b()) {
                    this.a.d(this);
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final boolean b() {
        a aVar = this.d;
        if (aVar != null && aVar.b) {
            this.f = true;
        }
        ArrayList arrayList = this.e;
        boolean z = false;
        for (int size = arrayList.size() - 1; -1 < size; size--) {
            if (((a) arrayList.get(size)).b) {
                a aVar2 = (a) arrayList.get(size);
                if (d.i.isLoggable(Level.FINE)) {
                    AbstractC3363l2.b(aVar2, this, "canceled");
                }
                arrayList.remove(size);
                z = true;
            }
        }
        return z;
    }

    public final void c(a task, long j) {
        Intrinsics.checkNotNullParameter(task, "task");
        synchronized (this.a) {
            if (!this.c) {
                if (d(task, j, false)) {
                    this.a.d(this);
                }
                Unit unit = Unit.a;
            } else if (task.b) {
                if (d.i.isLoggable(Level.FINE)) {
                    AbstractC3363l2.b(task, this, "schedule canceled (queue is shutdown)");
                }
            } else {
                if (d.i.isLoggable(Level.FINE)) {
                    AbstractC3363l2.b(task, this, "schedule failed (queue is shutdown)");
                }
                throw new RejectedExecutionException();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x004f  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0076  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0093 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0087 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean d(okhttp3.internal.concurrent.a r11, long r12, boolean r14) {
        /*
            r10 = this;
            java.lang.String r0 = "task"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r11, r0)
            r11.getClass()
            java.lang.String r0 = "queue"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r0)
            okhttp3.internal.concurrent.c r0 = r11.c
            if (r0 != r10) goto L12
            goto L16
        L12:
            if (r0 != 0) goto L96
            r11.c = r10
        L16:
            okhttp3.internal.concurrent.d r0 = r10.a
            com.quizlet.login.authentication.login.a r0 = r0.a
            long r0 = java.lang.System.nanoTime()
            long r2 = r0 + r12
            java.util.ArrayList r4 = r10.e
            int r5 = r4.indexOf(r11)
            r6 = 0
            r7 = -1
            if (r5 == r7) goto L43
            long r8 = r11.d
            int r8 = (r8 > r2 ? 1 : (r8 == r2 ? 0 : -1))
            if (r8 > 0) goto L40
            java.util.logging.Logger r12 = okhttp3.internal.concurrent.d.i
            java.util.logging.Level r13 = java.util.logging.Level.FINE
            boolean r12 = r12.isLoggable(r13)
            if (r12 == 0) goto L95
            java.lang.String r12 = "already scheduled"
            com.google.android.gms.internal.mlkit_vision_camera.AbstractC3363l2.b(r11, r10, r12)
            return r6
        L40:
            r4.remove(r5)
        L43:
            r11.d = r2
            java.util.logging.Logger r5 = okhttp3.internal.concurrent.d.i
            java.util.logging.Level r8 = java.util.logging.Level.FINE
            boolean r5 = r5.isLoggable(r8)
            if (r5 == 0) goto L6b
            if (r14 == 0) goto L5d
            long r2 = r2 - r0
            java.lang.String r14 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3363l2.d(r2)
            java.lang.String r2 = "run again after "
            java.lang.String r14 = r2.concat(r14)
            goto L68
        L5d:
            long r2 = r2 - r0
            java.lang.String r14 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3363l2.d(r2)
            java.lang.String r2 = "scheduled after "
            java.lang.String r14 = r2.concat(r14)
        L68:
            com.google.android.gms.internal.mlkit_vision_camera.AbstractC3363l2.b(r11, r10, r14)
        L6b:
            java.util.Iterator r14 = r4.iterator()
            r2 = r6
        L70:
            boolean r3 = r14.hasNext()
            if (r3 == 0) goto L87
            java.lang.Object r3 = r14.next()
            okhttp3.internal.concurrent.a r3 = (okhttp3.internal.concurrent.a) r3
            long r8 = r3.d
            long r8 = r8 - r0
            int r3 = (r8 > r12 ? 1 : (r8 == r12 ? 0 : -1))
            if (r3 <= 0) goto L84
            goto L88
        L84:
            int r2 = r2 + 1
            goto L70
        L87:
            r2 = r7
        L88:
            if (r2 != r7) goto L8e
            int r2 = r4.size()
        L8e:
            r4.add(r2, r11)
            if (r2 != 0) goto L95
            r11 = 1
            return r11
        L95:
            return r6
        L96:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "task is in multiple queues"
            r11.<init>(r12)
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.concurrent.c.d(okhttp3.internal.concurrent.a, long, boolean):boolean");
    }

    public final void e() {
        byte[] bArr = okhttp3.internal.b.a;
        synchronized (this.a) {
            try {
                this.c = true;
                if (b()) {
                    this.a.d(this);
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final String toString() {
        return this.b;
    }
}
