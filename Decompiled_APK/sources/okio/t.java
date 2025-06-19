package okio;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class t extends n {
    public static ArrayList Q(x xVar, boolean z) throws IOException {
        File fileG = xVar.g();
        String[] list = fileG.list();
        if (list == null) {
            if (!z) {
                return null;
            }
            if (fileG.exists()) {
                throw new IOException("failed to list " + xVar);
            }
            throw new FileNotFoundException("no such file: " + xVar);
        }
        ArrayList arrayList = new ArrayList();
        for (String str : list) {
            Intrinsics.d(str);
            arrayList.add(xVar.e(str));
        }
        kotlin.collections.F.s(arrayList);
        return arrayList;
    }

    @Override // okio.n
    public androidx.constraintlayout.core.widgets.analyzer.f B(x path) {
        Intrinsics.checkNotNullParameter(path, "path");
        File fileG = path.g();
        boolean zIsFile = fileG.isFile();
        boolean zIsDirectory = fileG.isDirectory();
        long jLastModified = fileG.lastModified();
        long length = fileG.length();
        if (!zIsFile && !zIsDirectory && jLastModified == 0 && length == 0 && !fileG.exists()) {
            return null;
        }
        return new androidx.constraintlayout.core.widgets.analyzer.f(zIsFile, zIsDirectory, null, Long.valueOf(length), null, Long.valueOf(jLastModified), null);
    }

    @Override // okio.n
    public final s C(x file) {
        Intrinsics.checkNotNullParameter(file, "file");
        return new s(false, new RandomAccessFile(file.g(), "r"));
    }

    @Override // okio.n
    public final E D(x file, boolean z) throws IOException {
        Intrinsics.checkNotNullParameter(file, "file");
        if (z && p(file)) {
            throw new IOException(file + " already exists.");
        }
        File fileG = file.g();
        Logger logger = v.a;
        Intrinsics.checkNotNullParameter(fileG, "<this>");
        FileOutputStream fileOutputStream = new FileOutputStream(fileG, false);
        Intrinsics.checkNotNullParameter(fileOutputStream, "<this>");
        return new C5086c(fileOutputStream, new I());
    }

    @Override // okio.n
    public final G P(x file) {
        Intrinsics.checkNotNullParameter(file, "file");
        return AbstractC5085b.i(file.g());
    }

    @Override // okio.n
    public final E a(x file, boolean z) throws IOException {
        Intrinsics.checkNotNullParameter(file, "file");
        if (z && !p(file)) {
            throw new IOException(file + " doesn't exist.");
        }
        File fileG = file.g();
        Logger logger = v.a;
        Intrinsics.checkNotNullParameter(fileG, "<this>");
        FileOutputStream fileOutputStream = new FileOutputStream(fileG, true);
        Intrinsics.checkNotNullParameter(fileOutputStream, "<this>");
        return new C5086c(fileOutputStream, new I());
    }

    @Override // okio.n
    public void d(x source, x target) throws IOException {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(target, "target");
        if (source.g().renameTo(target.g())) {
            return;
        }
        throw new IOException("failed to move " + source + " to " + target);
    }

    @Override // okio.n
    public final void i(x dir) throws IOException {
        Intrinsics.checkNotNullParameter(dir, "dir");
        if (dir.g().mkdir()) {
            return;
        }
        androidx.constraintlayout.core.widgets.analyzer.f fVarB = B(dir);
        if (fVarB == null || !fVarB.c) {
            throw new IOException("failed to create directory: " + dir);
        }
    }

    @Override // okio.n
    public final void l(x path, boolean z) throws IOException {
        Intrinsics.checkNotNullParameter(path, "path");
        if (Thread.interrupted()) {
            throw new InterruptedIOException("interrupted");
        }
        File fileG = path.g();
        if (fileG.delete()) {
            return;
        }
        if (fileG.exists()) {
            throw new IOException("failed to delete " + path);
        }
        if (z) {
            throw new FileNotFoundException("no such file: " + path);
        }
    }

    @Override // okio.n
    public final List q(x dir) throws IOException {
        Intrinsics.checkNotNullParameter(dir, "dir");
        ArrayList arrayListQ = Q(dir, true);
        Intrinsics.d(arrayListQ);
        return arrayListQ;
    }

    @Override // okio.n
    public final List r(x dir) {
        Intrinsics.checkNotNullParameter(dir, "dir");
        return Q(dir, false);
    }

    public String toString() {
        return "JvmSystemFileSystem";
    }
}
