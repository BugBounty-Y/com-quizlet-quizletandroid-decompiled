package androidx.loader.content;

import android.content.Context;
import android.os.Looper;
import androidx.annotation.NonNull;
import java.io.FileDescriptor;
import java.io.PrintWriter;

/* loaded from: classes.dex */
public class c {
    public int a;
    public androidx.loader.app.c b;
    public final Context c;
    public boolean d = false;
    public boolean e = false;
    public boolean f = true;
    public boolean g = false;

    public c(@NonNull Context context) {
        this.c = context.getApplicationContext();
    }

    public void a(Object obj) {
        androidx.loader.app.c cVar = this.b;
        if (cVar != null) {
            if (Looper.myLooper() == Looper.getMainLooper()) {
                cVar.l(obj);
            } else {
                cVar.j(obj);
            }
        }
    }

    public void b(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        printWriter.print(str);
        printWriter.print("mId=");
        printWriter.print(this.a);
        printWriter.print(" mListener=");
        printWriter.println(this.b);
        if (this.d || this.g) {
            printWriter.print(str);
            printWriter.print("mStarted=");
            printWriter.print(this.d);
            printWriter.print(" mContentChanged=");
            printWriter.print(this.g);
            printWriter.print(" mProcessingChange=");
            printWriter.println(false);
        }
        if (this.e || this.f) {
            printWriter.print(str);
            printWriter.print("mAbandoned=");
            printWriter.print(this.e);
            printWriter.print(" mReset=");
            printWriter.println(this.f);
        }
    }

    public boolean c() {
        return false;
    }

    public void d() {
    }

    public void e() {
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder(64);
        Class<?> cls = getClass();
        sb.append(cls.getSimpleName());
        sb.append("{");
        sb.append(Integer.toHexString(System.identityHashCode(cls)));
        sb.append(" id=");
        return android.support.v4.media.session.a.r(sb, this.a, "}");
    }
}
