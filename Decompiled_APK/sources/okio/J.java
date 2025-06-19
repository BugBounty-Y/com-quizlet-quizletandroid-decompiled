package okio;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.zip.Inflater;
import kotlin.C4937f;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class J extends n {
    public static final x f;
    public final x c;
    public final n d;
    public final LinkedHashMap e;

    static {
        String str = x.b;
        f = com.quizlet.quizletandroid.ui.folder.logging.a.f("/", false);
    }

    public J(x zipPath, n fileSystem, LinkedHashMap entries) {
        Intrinsics.checkNotNullParameter(zipPath, "zipPath");
        Intrinsics.checkNotNullParameter(fileSystem, "fileSystem");
        Intrinsics.checkNotNullParameter(entries, "entries");
        this.c = zipPath;
        this.d = fileSystem;
        this.e = entries;
    }

    /* JADX WARN: Removed duplicated region for block: B:64:0x0128  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0136  */
    @Override // okio.n
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.constraintlayout.core.widgets.analyzer.f B(okio.x r26) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 332
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okio.J.B(okio.x):androidx.constraintlayout.core.widgets.analyzer.f");
    }

    @Override // okio.n
    public final s C(x file) {
        Intrinsics.checkNotNullParameter(file, "file");
        throw new UnsupportedOperationException("not implemented yet!");
    }

    @Override // okio.n
    public final E D(x file, boolean z) throws IOException {
        Intrinsics.checkNotNullParameter(file, "file");
        throw new IOException("zip file systems are read-only");
    }

    @Override // okio.n
    public final G P(x child) throws Throwable {
        Throwable th;
        A aC;
        Intrinsics.checkNotNullParameter(child, "file");
        x xVar = f;
        xVar.getClass();
        Intrinsics.checkNotNullParameter(child, "child");
        okio.internal.h hVar = (okio.internal.h) this.e.get(okio.internal.e.b(xVar, child, true));
        if (hVar == null) {
            throw new FileNotFoundException("no such file: " + child);
        }
        s sVarC = this.d.C(this.c);
        try {
            aC = AbstractC5085b.c(sVarC.f(hVar.h));
            try {
                sVarC.close();
                th = null;
            } catch (Throwable th2) {
                th = th2;
            }
        } catch (Throwable th3) {
            if (sVarC != null) {
                try {
                    sVarC.close();
                } catch (Throwable th4) {
                    C4937f.a(th3, th4);
                }
            }
            th = th3;
            aC = null;
        }
        if (th != null) {
            throw th;
        }
        Intrinsics.checkNotNullParameter(aC, "<this>");
        okio.internal.b.h(aC, null);
        int i = hVar.g;
        long j = hVar.f;
        if (i == 0) {
            return new okio.internal.f(aC, j, true);
        }
        okio.internal.f source = new okio.internal.f(aC, hVar.e, true);
        Inflater inflater = new Inflater(true);
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new okio.internal.f(new r(AbstractC5085b.c(source), inflater), j, false);
    }

    public final List Q(x child, boolean z) throws IOException {
        x xVar = f;
        xVar.getClass();
        Intrinsics.checkNotNullParameter(child, "child");
        okio.internal.h hVar = (okio.internal.h) this.e.get(okio.internal.e.b(xVar, child, true));
        if (hVar != null) {
            return CollectionsKt.w0(hVar.q);
        }
        if (!z) {
            return null;
        }
        throw new IOException("not a directory: " + child);
    }

    @Override // okio.n
    public final E a(x file, boolean z) throws IOException {
        Intrinsics.checkNotNullParameter(file, "file");
        throw new IOException("zip file systems are read-only");
    }

    @Override // okio.n
    public final void d(x source, x target) throws IOException {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(target, "target");
        throw new IOException("zip file systems are read-only");
    }

    @Override // okio.n
    public final void i(x dir) throws IOException {
        Intrinsics.checkNotNullParameter(dir, "dir");
        throw new IOException("zip file systems are read-only");
    }

    @Override // okio.n
    public final void l(x path, boolean z) throws IOException {
        Intrinsics.checkNotNullParameter(path, "path");
        throw new IOException("zip file systems are read-only");
    }

    @Override // okio.n
    public final List q(x dir) throws IOException {
        Intrinsics.checkNotNullParameter(dir, "dir");
        List listQ = Q(dir, true);
        Intrinsics.d(listQ);
        return listQ;
    }

    @Override // okio.n
    public final List r(x dir) {
        Intrinsics.checkNotNullParameter(dir, "dir");
        return Q(dir, false);
    }
}
