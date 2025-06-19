package coil3.disk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.collections.F;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import okio.E;
import okio.G;
import okio.n;
import okio.s;
import okio.t;
import okio.x;

/* loaded from: classes.dex */
public final class c extends n {
    public final t c;

    public c(t delegate) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.c = delegate;
    }

    public static void Q(x path, String functionName, String parameterName) {
        Intrinsics.checkNotNullParameter(path, "path");
        Intrinsics.checkNotNullParameter(functionName, "functionName");
        Intrinsics.checkNotNullParameter(parameterName, "parameterName");
    }

    @Override // okio.n
    public final androidx.constraintlayout.core.widgets.analyzer.f B(x path) {
        Intrinsics.checkNotNullParameter(path, "path");
        Q(path, "metadataOrNull", "path");
        androidx.constraintlayout.core.widgets.analyzer.f fVarB = this.c.B(path);
        if (fVarB == null) {
            return null;
        }
        x path2 = (x) fVarB.d;
        if (path2 == null) {
            return fVarB;
        }
        Intrinsics.checkNotNullParameter(path2, "path");
        Intrinsics.checkNotNullParameter("metadataOrNull", "functionName");
        Map extras = (Map) fVarB.i;
        Intrinsics.checkNotNullParameter(extras, "extras");
        return new androidx.constraintlayout.core.widgets.analyzer.f(fVarB.b, fVarB.c, path2, (Long) fVarB.e, (Long) fVarB.f, (Long) fVarB.g, (Long) fVarB.h, extras);
    }

    @Override // okio.n
    public final s C(x file) {
        Intrinsics.checkNotNullParameter(file, "file");
        Q(file, "openReadOnly", "file");
        return this.c.C(file);
    }

    @Override // okio.n
    public final E D(x file, boolean z) {
        x dir = file.c();
        if (dir != null) {
            Intrinsics.checkNotNullParameter(dir, "dir");
            f(dir);
        }
        Intrinsics.checkNotNullParameter(file, "file");
        Q(file, "sink", "file");
        return this.c.D(file, z);
    }

    @Override // okio.n
    public final G P(x file) {
        Intrinsics.checkNotNullParameter(file, "file");
        Q(file, "source", "file");
        return this.c.P(file);
    }

    @Override // okio.n
    public final E a(x file, boolean z) {
        Intrinsics.checkNotNullParameter(file, "file");
        Q(file, "appendingSink", "file");
        return this.c.a(file, z);
    }

    @Override // okio.n, java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        this.c.getClass();
    }

    @Override // okio.n
    public final void d(x source, x target) throws IOException {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(target, "target");
        Q(source, "atomicMove", "source");
        Q(target, "atomicMove", "target");
        this.c.d(source, target);
    }

    @Override // okio.n
    public final void i(x dir) throws IOException {
        Intrinsics.checkNotNullParameter(dir, "dir");
        Q(dir, "createDirectory", "dir");
        this.c.i(dir);
    }

    @Override // okio.n
    public final void l(x path, boolean z) throws IOException {
        Intrinsics.checkNotNullParameter(path, "path");
        Q(path, "delete", "path");
        this.c.l(path, z);
    }

    @Override // okio.n
    public final List q(x dir) throws IOException {
        Intrinsics.checkNotNullParameter(dir, "dir");
        Q(dir, "list", "dir");
        List listQ = this.c.q(dir);
        ArrayList arrayList = new ArrayList();
        Iterator it2 = ((ArrayList) listQ).iterator();
        while (it2.hasNext()) {
            x path = (x) it2.next();
            Intrinsics.checkNotNullParameter(path, "path");
            Intrinsics.checkNotNullParameter("list", "functionName");
            arrayList.add(path);
        }
        F.s(arrayList);
        return arrayList;
    }

    @Override // okio.n
    public final List r(x dir) {
        Intrinsics.checkNotNullParameter(dir, "dir");
        Q(dir, "listOrNull", "dir");
        List listR = this.c.r(dir);
        if (listR == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList();
        Iterator it2 = ((ArrayList) listR).iterator();
        while (it2.hasNext()) {
            x path = (x) it2.next();
            Intrinsics.checkNotNullParameter(path, "path");
            Intrinsics.checkNotNullParameter("listOrNull", "functionName");
            arrayList.add(path);
        }
        F.s(arrayList);
        return arrayList;
    }

    public final String toString() {
        return K.a(c.class).f() + '(' + this.c + ')';
    }
}
