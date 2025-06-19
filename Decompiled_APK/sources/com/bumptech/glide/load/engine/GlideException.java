package com.bumptech.glide.load.engine;

import android.util.Log;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public final class GlideException extends Exception {
    public static final StackTraceElement[] f = new StackTraceElement[0];
    public final List a;
    public com.bumptech.glide.load.e b;
    public int c;
    public Class d;
    public final String e;

    public GlideException(String str) {
        this(str, Collections.EMPTY_LIST);
    }

    public static void a(Throwable th, ArrayList arrayList) {
        if (!(th instanceof GlideException)) {
            arrayList.add(th);
            return;
        }
        Iterator it2 = ((GlideException) th).a.iterator();
        while (it2.hasNext()) {
            a((Throwable) it2.next(), arrayList);
        }
    }

    public static void b(List list, r rVar) throws IOException {
        int size = list.size();
        int i = 0;
        while (i < size) {
            rVar.append("Cause (");
            int i2 = i + 1;
            rVar.append(String.valueOf(i2));
            rVar.append(" of ");
            rVar.append(String.valueOf(size));
            rVar.append("): ");
            Throwable th = (Throwable) list.get(i);
            if (th instanceof GlideException) {
                ((GlideException) th).e(rVar);
            } else {
                c(th, rVar);
            }
            i = i2;
        }
    }

    public static void c(Throwable th, Appendable appendable) throws IOException {
        try {
            appendable.append(th.getClass().toString()).append(": ").append(th.getMessage()).append('\n');
        } catch (IOException unused) {
            throw new RuntimeException(th);
        }
    }

    public final void d() {
        ArrayList arrayList = new ArrayList();
        a(this, arrayList);
        int size = arrayList.size();
        int i = 0;
        while (i < size) {
            StringBuilder sb = new StringBuilder("Root cause (");
            int i2 = i + 1;
            sb.append(i2);
            sb.append(" of ");
            sb.append(size);
            sb.append(")");
            Log.i("Glide", sb.toString(), (Throwable) arrayList.get(i));
            i = i2;
        }
    }

    public final void e(Appendable appendable) throws IOException {
        c(this, appendable);
        try {
            b(this.a, new r(appendable));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override // java.lang.Throwable
    public final Throwable fillInStackTrace() {
        return this;
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        String str;
        String strConcat;
        StringBuilder sb = new StringBuilder(71);
        sb.append(this.e);
        String str2 = "";
        if (this.d != null) {
            str = ", " + this.d;
        } else {
            str = "";
        }
        sb.append(str);
        int i = this.c;
        if (i != 0) {
            strConcat = ", ".concat(i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? "null" : "MEMORY_CACHE" : "RESOURCE_DISK_CACHE" : "DATA_DISK_CACHE" : "REMOTE" : "LOCAL");
        } else {
            strConcat = "";
        }
        sb.append(strConcat);
        if (this.b != null) {
            str2 = ", " + this.b;
        }
        sb.append(str2);
        ArrayList arrayList = new ArrayList();
        a(this, arrayList);
        if (arrayList.isEmpty()) {
            return sb.toString();
        }
        if (arrayList.size() == 1) {
            sb.append("\nThere was 1 root cause:");
        } else {
            sb.append("\nThere were ");
            sb.append(arrayList.size());
            sb.append(" root causes:");
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Throwable th = (Throwable) it2.next();
            sb.append('\n');
            sb.append(th.getClass().getName());
            sb.append('(');
            sb.append(th.getMessage());
            sb.append(')');
        }
        sb.append("\n call GlideException#logRootCauses(String) for more detail");
        return sb.toString();
    }

    @Override // java.lang.Throwable
    public final void printStackTrace() throws IOException {
        e(System.err);
    }

    public GlideException(String str, List list) {
        this.e = str;
        setStackTrace(f);
        this.a = list;
    }

    @Override // java.lang.Throwable
    public final void printStackTrace(PrintStream printStream) throws IOException {
        e(printStream);
    }

    @Override // java.lang.Throwable
    public final void printStackTrace(PrintWriter printWriter) throws IOException {
        e(printWriter);
    }
}
