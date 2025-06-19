package androidx.loader.content;

import android.content.Context;
import android.os.AsyncTask;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public abstract class b extends c {
    public Executor h;
    public volatile a i;
    public volatile a j;

    public b(@NonNull Context context) {
        super(context);
    }

    @Override // androidx.loader.content.c
    public final void b(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        super.b(str, fileDescriptor, printWriter, strArr);
        if (this.i != null) {
            printWriter.print(str);
            printWriter.print("mTask=");
            printWriter.print(this.i);
            printWriter.print(" waiting=");
            this.i.getClass();
            printWriter.println(false);
        }
        if (this.j != null) {
            printWriter.print(str);
            printWriter.print("mCancellingTask=");
            printWriter.print(this.j);
            printWriter.print(" waiting=");
            this.j.getClass();
            printWriter.println(false);
        }
    }

    @Override // androidx.loader.content.c
    public final boolean c() {
        if (this.i == null) {
            return false;
        }
        boolean z = this.d;
        if (!z) {
            if (z) {
                h();
            } else {
                this.g = true;
            }
        }
        if (this.j != null) {
            this.i.getClass();
            this.i = null;
            return false;
        }
        this.i.getClass();
        a aVar = this.i;
        aVar.c.set(true);
        boolean zCancel = aVar.a.cancel(false);
        if (zCancel) {
            this.j = this.i;
        }
        this.i = null;
        return zCancel;
    }

    public final void f() {
        if (this.j != null || this.i == null) {
            return;
        }
        this.i.getClass();
        if (this.h == null) {
            this.h = AsyncTask.THREAD_POOL_EXECUTOR;
        }
        a aVar = this.i;
        Executor executor = this.h;
        if (aVar.b == 1) {
            aVar.b = 2;
            executor.execute(aVar.a);
            return;
        }
        int iK = AbstractC0147y.k(aVar.b);
        if (iK == 1) {
            throw new IllegalStateException("Cannot execute task: the task is already running.");
        }
        if (iK == 2) {
            throw new IllegalStateException("Cannot execute task: the task has already been executed (a task can be executed only once)");
        }
        throw new IllegalStateException("We should never reach this state");
    }

    public abstract Object g();

    public final void h() {
        c();
        this.i = new a(this);
        f();
    }
}
