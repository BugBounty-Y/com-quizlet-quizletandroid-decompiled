package okio;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x implements Comparable {
    public static final String b;
    public final k a;

    static {
        String separator = File.separator;
        Intrinsics.checkNotNullExpressionValue(separator, "separator");
        b = separator;
    }

    public x(k bytes) {
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        this.a = bytes;
    }

    public static x f(x xVar, String child) {
        xVar.getClass();
        Intrinsics.checkNotNullParameter(child, "child");
        C5091h c5091h = new C5091h();
        c5091h.u0(child);
        return okio.internal.e.b(xVar, okio.internal.e.d(c5091h, false), false);
    }

    public final ArrayList a() {
        ArrayList arrayList = new ArrayList();
        int iA = okio.internal.e.a(this);
        k kVar = this.a;
        if (iA == -1) {
            iA = 0;
        } else if (iA < kVar.d() && kVar.j(iA) == 92) {
            iA++;
        }
        int iD = kVar.d();
        int i = iA;
        while (iA < iD) {
            if (kVar.j(iA) == 47 || kVar.j(iA) == 92) {
                arrayList.add(kVar.o(i, iA));
                i = iA + 1;
            }
            iA++;
        }
        if (i < kVar.d()) {
            arrayList.add(kVar.o(i, kVar.d()));
        }
        return arrayList;
    }

    public final String b() {
        k kVar = okio.internal.e.a;
        k kVar2 = okio.internal.e.a;
        k kVarP = this.a;
        int iL = k.l(kVarP, kVar2);
        if (iL == -1) {
            iL = k.l(kVarP, okio.internal.e.b);
        }
        if (iL != -1) {
            kVarP = k.p(kVarP, iL + 1, 0, 2);
        } else if (i() != null && kVarP.d() == 2) {
            kVarP = k.d;
        }
        return kVarP.s();
    }

    public final x c() {
        k kVar = okio.internal.e.d;
        k kVar2 = this.a;
        if (Intrinsics.b(kVar2, kVar)) {
            return null;
        }
        k kVar3 = okio.internal.e.a;
        if (Intrinsics.b(kVar2, kVar3)) {
            return null;
        }
        k prefix = okio.internal.e.b;
        if (Intrinsics.b(kVar2, prefix)) {
            return null;
        }
        k suffix = okio.internal.e.e;
        kVar2.getClass();
        Intrinsics.checkNotNullParameter(suffix, "suffix");
        int iD = kVar2.d();
        byte[] bArr = suffix.a;
        if (kVar2.n(iD - bArr.length, suffix, bArr.length) && (kVar2.d() == 2 || kVar2.n(kVar2.d() - 3, kVar3, 1) || kVar2.n(kVar2.d() - 3, prefix, 1))) {
            return null;
        }
        int iL = k.l(kVar2, kVar3);
        if (iL == -1) {
            iL = k.l(kVar2, prefix);
        }
        if (iL == 2 && i() != null) {
            if (kVar2.d() == 3) {
                return null;
            }
            return new x(k.p(kVar2, 0, 3, 1));
        }
        if (iL == 1) {
            Intrinsics.checkNotNullParameter(prefix, "prefix");
            if (kVar2.n(0, prefix, prefix.d())) {
                return null;
            }
        }
        if (iL != -1 || i() == null) {
            return iL == -1 ? new x(kVar) : iL == 0 ? new x(k.p(kVar2, 0, 1, 1)) : new x(k.p(kVar2, 0, iL, 1));
        }
        if (kVar2.d() == 2) {
            return null;
        }
        return new x(k.p(kVar2, 0, 2, 1));
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        x other = (x) obj;
        Intrinsics.checkNotNullParameter(other, "other");
        return this.a.compareTo(other.a);
    }

    public final x d(x other) {
        Intrinsics.checkNotNullParameter(other, "other");
        int iA = okio.internal.e.a(this);
        k kVar = this.a;
        x xVar = iA == -1 ? null : new x(kVar.o(0, iA));
        other.getClass();
        int iA2 = okio.internal.e.a(other);
        k kVar2 = other.a;
        if (!Intrinsics.b(xVar, iA2 != -1 ? new x(kVar2.o(0, iA2)) : null)) {
            throw new IllegalArgumentException(("Paths of different roots cannot be relative to each other: " + this + " and " + other).toString());
        }
        ArrayList arrayListA = a();
        ArrayList arrayListA2 = other.a();
        int iMin = Math.min(arrayListA.size(), arrayListA2.size());
        int i = 0;
        while (i < iMin && Intrinsics.b(arrayListA.get(i), arrayListA2.get(i))) {
            i++;
        }
        if (i == iMin && kVar.d() == kVar2.d()) {
            return com.quizlet.quizletandroid.ui.folder.logging.a.f(".", false);
        }
        if (arrayListA2.subList(i, arrayListA2.size()).indexOf(okio.internal.e.e) != -1) {
            throw new IllegalArgumentException(("Impossible relative path to resolve: " + this + " and " + other).toString());
        }
        if (Intrinsics.b(kVar2, okio.internal.e.d)) {
            return this;
        }
        C5091h c5091h = new C5091h();
        k kVarC = okio.internal.e.c(other);
        if (kVarC == null && (kVarC = okio.internal.e.c(this)) == null) {
            kVarC = okio.internal.e.f(b);
        }
        int size = arrayListA2.size();
        for (int i2 = i; i2 < size; i2++) {
            c5091h.m0(okio.internal.e.e);
            c5091h.m0(kVarC);
        }
        int size2 = arrayListA.size();
        while (i < size2) {
            c5091h.m0((k) arrayListA.get(i));
            c5091h.m0(kVarC);
            i++;
        }
        return okio.internal.e.d(c5091h, false);
    }

    public final x e(String child) {
        Intrinsics.checkNotNullParameter(child, "child");
        C5091h c5091h = new C5091h();
        c5091h.u0(child);
        return okio.internal.e.b(this, okio.internal.e.d(c5091h, false), false);
    }

    public final boolean equals(Object obj) {
        return (obj instanceof x) && Intrinsics.b(((x) obj).a, this.a);
    }

    public final File g() {
        return new File(this.a.s());
    }

    public final Path h() {
        Path path = Paths.get(this.a.s(), new String[0]);
        Intrinsics.checkNotNullExpressionValue(path, "get(...)");
        return path;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final Character i() {
        k kVar = okio.internal.e.a;
        k kVar2 = this.a;
        if (k.g(kVar2, kVar) != -1 || kVar2.d() < 2 || kVar2.j(1) != 58) {
            return null;
        }
        char cJ = (char) kVar2.j(0);
        if (('a' > cJ || cJ >= '{') && ('A' > cJ || cJ >= '[')) {
            return null;
        }
        return Character.valueOf(cJ);
    }

    public final String toString() {
        return this.a.s();
    }
}
