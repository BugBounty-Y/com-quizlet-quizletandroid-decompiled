package kotlin.io;

import assistantMode.types.q;
import java.io.File;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Iterator;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.AbstractC4912c;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends AbstractC4912c {
    public final /* synthetic */ int c = 1;
    public final Object d;
    public final Object e;

    public e(Iterator source) {
        assistantMode.tasks.sequencing.a keySelector = assistantMode.tasks.sequencing.a.a;
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(keySelector, "keySelector");
        this.d = source;
        this.e = new HashSet();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Override // kotlin.collections.AbstractC4912c
    public final void a() {
        File file;
        File fileA;
        Object next;
        q it2;
        switch (this.c) {
            case 0:
                while (true) {
                    ArrayDeque arrayDeque = (ArrayDeque) this.d;
                    f fVar = (f) arrayDeque.peek();
                    if (fVar == null) {
                        file = null;
                    } else {
                        fileA = fVar.a();
                        if (fileA == null) {
                            arrayDeque.pop();
                        } else if (!fileA.equals(fVar.a) && fileA.isDirectory() && arrayDeque.size() < ((g) this.e).f) {
                            arrayDeque.push(b(fileA));
                        }
                    }
                }
                file = fileA;
                if (file == null) {
                    this.a = 2;
                    break;
                } else {
                    this.b = file;
                    this.a = 1;
                    break;
                }
                break;
            default:
                do {
                    Iterator it3 = (Iterator) this.d;
                    if (!it3.hasNext()) {
                        this.a = 2;
                        break;
                    } else {
                        next = it3.next();
                        it2 = (q) next;
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                } while (!((HashSet) this.e).add(Long.valueOf(it2.a)));
                this.b = next;
                this.a = 1;
                break;
        }
    }

    public a b(File file) {
        int iOrdinal = ((g) this.e).b.ordinal();
        if (iOrdinal == 0) {
            return new d(this, file);
        }
        if (iOrdinal == 1) {
            return new b(this, file);
        }
        throw new NoWhenBranchMatchedException();
    }

    public e(g gVar) {
        this.e = gVar;
        ArrayDeque arrayDeque = new ArrayDeque();
        this.d = arrayDeque;
        if (gVar.a.isDirectory()) {
            arrayDeque.push(b(gVar.a));
        } else {
            if (gVar.a.isFile()) {
                File rootFile = gVar.a;
                Intrinsics.checkNotNullParameter(rootFile, "rootFile");
                arrayDeque.push(new c(rootFile));
                return;
            }
            this.a = 2;
        }
    }
}
