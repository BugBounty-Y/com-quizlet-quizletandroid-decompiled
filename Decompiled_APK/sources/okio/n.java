package okio;

import java.io.Closeable;
import java.io.FileNotFoundException;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C4927s;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class n implements Closeable, AutoCloseable {
    public static final t a;
    public static final x b;

    static {
        t tVar;
        try {
            Class.forName("java.nio.file.Files");
            tVar = new u();
        } catch (ClassNotFoundException unused) {
            tVar = new t();
        }
        a = tVar;
        String str = x.b;
        String property = System.getProperty("java.io.tmpdir");
        Intrinsics.checkNotNullExpressionValue(property, "getProperty(...)");
        b = com.quizlet.quizletandroid.ui.folder.logging.a.f(property, false);
        ClassLoader classLoader = okio.internal.g.class.getClassLoader();
        Intrinsics.checkNotNullExpressionValue(classLoader, "getClassLoader(...)");
        new okio.internal.g(classLoader);
    }

    public abstract androidx.constraintlayout.core.widgets.analyzer.f B(x xVar);

    public abstract s C(x xVar);

    public abstract E D(x xVar, boolean z);

    public abstract G P(x xVar);

    public abstract E a(x xVar, boolean z);

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
    }

    public abstract void d(x xVar, x xVar2);

    public final void f(x dir) {
        Intrinsics.checkNotNullParameter(dir, "dir");
        Intrinsics.checkNotNullParameter(this, "<this>");
        Intrinsics.checkNotNullParameter(dir, "dir");
        C4927s c4927s = new C4927s();
        while (dir != null && !p(dir)) {
            c4927s.addFirst(dir);
            dir = dir.c();
        }
        Iterator<E> it2 = c4927s.iterator();
        while (it2.hasNext()) {
            i((x) it2.next());
        }
    }

    public abstract void i(x xVar);

    public final void j(x path) {
        Intrinsics.checkNotNullParameter(path, "path");
        l(path, false);
    }

    public abstract void l(x xVar, boolean z);

    public final boolean p(x path) {
        Intrinsics.checkNotNullParameter(path, "path");
        Intrinsics.checkNotNullParameter(this, "<this>");
        Intrinsics.checkNotNullParameter(path, "path");
        return B(path) != null;
    }

    public abstract List q(x xVar);

    public abstract List r(x xVar);

    public final androidx.constraintlayout.core.widgets.analyzer.f y(x path) throws FileNotFoundException {
        Intrinsics.checkNotNullParameter(path, "path");
        Intrinsics.checkNotNullParameter(this, "<this>");
        Intrinsics.checkNotNullParameter(path, "path");
        androidx.constraintlayout.core.widgets.analyzer.f fVarB = B(path);
        if (fVarB != null) {
            return fVarB;
        }
        throw new FileNotFoundException("no such file: " + path);
    }
}
