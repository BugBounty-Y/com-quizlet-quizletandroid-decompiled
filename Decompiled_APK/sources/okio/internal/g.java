package okio.internal;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;
import okio.AbstractC5085b;
import okio.E;
import okio.G;
import okio.n;
import okio.s;
import okio.t;
import okio.x;

/* loaded from: classes3.dex */
public final class g extends n {
    public static final x f;
    public final ClassLoader c;
    public final t d;
    public final u e;

    static {
        String str = x.b;
        f = com.quizlet.quizletandroid.ui.folder.logging.a.f("/", false);
    }

    public g(ClassLoader classLoader) {
        Intrinsics.checkNotNullParameter(classLoader, "classLoader");
        t systemFileSystem = n.a;
        Intrinsics.checkNotNullParameter(systemFileSystem, "systemFileSystem");
        this.c = classLoader;
        this.d = systemFileSystem;
        this.e = l.b(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 24));
    }

    public static String Q(x child) {
        x xVar = f;
        xVar.getClass();
        Intrinsics.checkNotNullParameter(child, "child");
        return e.b(xVar, child, true).d(xVar).a.s();
    }

    @Override // okio.n
    public final androidx.constraintlayout.core.widgets.analyzer.f B(x path) {
        Intrinsics.checkNotNullParameter(path, "path");
        if (!com.quizlet.quizletandroid.ui.joincontenttofolder.i.a(path)) {
            return null;
        }
        String strQ = Q(path);
        for (Pair pair : (List) this.e.getValue()) {
            androidx.constraintlayout.core.widgets.analyzer.f fVarB = ((n) pair.a).B(((x) pair.b).e(strQ));
            if (fVarB != null) {
                return fVarB;
            }
        }
        return null;
    }

    @Override // okio.n
    public final s C(x file) throws FileNotFoundException {
        Intrinsics.checkNotNullParameter(file, "file");
        if (!com.quizlet.quizletandroid.ui.joincontenttofolder.i.a(file)) {
            throw new FileNotFoundException("file not found: " + file);
        }
        String strQ = Q(file);
        for (Pair pair : (List) this.e.getValue()) {
            try {
                return ((n) pair.a).C(((x) pair.b).e(strQ));
            } catch (FileNotFoundException unused) {
            }
        }
        throw new FileNotFoundException("file not found: " + file);
    }

    @Override // okio.n
    public final E D(x file, boolean z) throws IOException {
        Intrinsics.checkNotNullParameter(file, "file");
        throw new IOException(this + " is read-only");
    }

    @Override // okio.n
    public final G P(x child) throws IOException {
        Intrinsics.checkNotNullParameter(child, "file");
        if (!com.quizlet.quizletandroid.ui.joincontenttofolder.i.a(child)) {
            throw new FileNotFoundException("file not found: " + child);
        }
        x xVar = f;
        xVar.getClass();
        Intrinsics.checkNotNullParameter(child, "child");
        URL resource = this.c.getResource(e.b(xVar, child, false).d(xVar).a.s());
        if (resource == null) {
            throw new FileNotFoundException("file not found: " + child);
        }
        URLConnection uRLConnectionOpenConnection = resource.openConnection();
        if (uRLConnectionOpenConnection instanceof JarURLConnection) {
            ((JarURLConnection) uRLConnectionOpenConnection).setUseCaches(false);
        }
        InputStream inputStream = uRLConnectionOpenConnection.getInputStream();
        Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
        return AbstractC5085b.j(inputStream);
    }

    @Override // okio.n
    public final E a(x file, boolean z) throws IOException {
        Intrinsics.checkNotNullParameter(file, "file");
        throw new IOException(this + " is read-only");
    }

    @Override // okio.n
    public final void d(x source, x target) throws IOException {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(target, "target");
        throw new IOException(this + " is read-only");
    }

    @Override // okio.n
    public final void i(x dir) throws IOException {
        Intrinsics.checkNotNullParameter(dir, "dir");
        throw new IOException(this + " is read-only");
    }

    @Override // okio.n
    public final void l(x path, boolean z) throws IOException {
        Intrinsics.checkNotNullParameter(path, "path");
        throw new IOException(this + " is read-only");
    }

    @Override // okio.n
    public final List q(x dir) throws FileNotFoundException {
        Intrinsics.checkNotNullParameter(dir, "dir");
        String strQ = Q(dir);
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        boolean z = false;
        for (Pair pair : (List) this.e.getValue()) {
            n nVar = (n) pair.a;
            x xVar = (x) pair.b;
            try {
                List listQ = nVar.q(xVar.e(strQ));
                ArrayList arrayList = new ArrayList();
                for (Object obj : listQ) {
                    if (com.quizlet.quizletandroid.ui.joincontenttofolder.i.a((x) obj)) {
                        arrayList.add(obj);
                    }
                }
                ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    arrayList2.add(com.quizlet.quizletandroid.ui.joincontenttofolder.i.d((x) it2.next(), xVar));
                }
                kotlin.collections.G.u(linkedHashSet, arrayList2);
                z = true;
            } catch (IOException unused) {
            }
        }
        if (z) {
            return CollectionsKt.w0(linkedHashSet);
        }
        throw new FileNotFoundException("file not found: " + dir);
    }

    @Override // okio.n
    public final List r(x dir) {
        Intrinsics.checkNotNullParameter(dir, "dir");
        String strQ = Q(dir);
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        Iterator it2 = ((List) this.e.getValue()).iterator();
        boolean z = false;
        while (true) {
            ArrayList arrayList = null;
            if (!it2.hasNext()) {
                break;
            }
            Pair pair = (Pair) it2.next();
            n nVar = (n) pair.a;
            x xVar = (x) pair.b;
            List listR = nVar.r(xVar.e(strQ));
            if (listR != null) {
                ArrayList arrayList2 = new ArrayList();
                for (Object obj : listR) {
                    if (com.quizlet.quizletandroid.ui.joincontenttofolder.i.a((x) obj)) {
                        arrayList2.add(obj);
                    }
                }
                ArrayList arrayList3 = new ArrayList(C.q(arrayList2, 10));
                Iterator it3 = arrayList2.iterator();
                while (it3.hasNext()) {
                    arrayList3.add(com.quizlet.quizletandroid.ui.joincontenttofolder.i.d((x) it3.next(), xVar));
                }
                arrayList = arrayList3;
            }
            if (arrayList != null) {
                kotlin.collections.G.u(linkedHashSet, arrayList);
                z = true;
            }
        }
        if (z) {
            return CollectionsKt.w0(linkedHashSet);
        }
        return null;
    }
}
