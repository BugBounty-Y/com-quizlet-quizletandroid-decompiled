package com.quizlet.quizletandroid.data.cache;

import com.quizlet.qutils.android.f;
import java.io.File;
import java.util.concurrent.atomic.AtomicLong;
import kotlin.io.FileWalkDirection;
import kotlin.io.g;
import kotlin.io.j;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.e;
import kotlin.sequences.q;

/* loaded from: classes3.dex */
public abstract class a {
    public final File a;

    public a(File file) {
        this.a = file;
    }

    public void a() {
        File[] fileArrListFiles = this.a.listFiles();
        if (fileArrListFiles != null) {
            for (File file : fileArrListFiles) {
                file.delete();
            }
        }
    }

    public abstract File b(String str);

    public abstract void c(File file, String str);

    public final long d() {
        File file = this.a;
        Intrinsics.checkNotNullParameter(file, "<this>");
        Intrinsics.checkNotNullParameter(file, "<this>");
        if (file.isFile()) {
            return file.length();
        }
        AtomicLong atomicLong = new AtomicLong(0L);
        g gVarD = j.d(file, FileWalkDirection.a);
        e eVar = new e(q.e(new g(gVarD.a, gVarD.b, gVarD.c, gVarD.d, gVarD.e, 2), new f(0)));
        while (eVar.hasNext()) {
            atomicLong.addAndGet(((File) eVar.next()).length());
        }
        return atomicLong.get();
    }
}
