package kotlin.sequences;

import androidx.collection.L;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.u;

/* loaded from: classes3.dex */
public class q extends o {
    public static int d(g gVar) {
        Intrinsics.checkNotNullParameter(gVar, "<this>");
        L l = new L(gVar);
        int i = 0;
        while (l.hasNext()) {
            l.next();
            i++;
            if (i < 0) {
                B.o();
                throw null;
            }
        }
        return i;
    }

    public static f e(Sequence sequence, Function1 predicate) {
        Intrinsics.checkNotNullParameter(sequence, "<this>");
        Intrinsics.checkNotNullParameter(predicate, "predicate");
        return new f(sequence, true, predicate);
    }

    public static f f(t tVar) {
        Intrinsics.checkNotNullParameter(tVar, "<this>");
        p predicate = p.a;
        Intrinsics.checkNotNullParameter(tVar, "<this>");
        Intrinsics.checkNotNullParameter(predicate, "predicate");
        return new f(tVar, false, predicate);
    }

    public static String g(Sequence sequence, String separator) {
        Intrinsics.checkNotNullParameter(sequence, "<this>");
        Intrinsics.checkNotNullParameter(separator, "separator");
        Intrinsics.checkNotNullParameter("", "prefix");
        Intrinsics.checkNotNullParameter("", "postfix");
        Intrinsics.checkNotNullParameter("...", "truncated");
        StringBuilder buffer = new StringBuilder();
        Intrinsics.checkNotNullParameter(sequence, "<this>");
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        Intrinsics.checkNotNullParameter(separator, "separator");
        Intrinsics.checkNotNullParameter("", "prefix");
        Intrinsics.checkNotNullParameter("", "postfix");
        Intrinsics.checkNotNullParameter("...", "truncated");
        buffer.append((CharSequence) "");
        int i = 0;
        for (Object obj : sequence) {
            i++;
            if (i > 1) {
                buffer.append((CharSequence) separator);
            }
            u.a(buffer, obj, null);
        }
        buffer.append((CharSequence) "");
        String string = buffer.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public static t h(Sequence sequence, Function1 transform) {
        Intrinsics.checkNotNullParameter(sequence, "<this>");
        Intrinsics.checkNotNullParameter(transform, "transform");
        return new t(sequence, transform, 1);
    }

    public static f i(Sequence sequence, Function1 transform) {
        Intrinsics.checkNotNullParameter(sequence, "<this>");
        Intrinsics.checkNotNullParameter(transform, "transform");
        return f(new t(sequence, transform, 1));
    }

    public static List j(Sequence sequence) {
        Intrinsics.checkNotNullParameter(sequence, "<this>");
        Iterator it2 = sequence.iterator();
        if (!it2.hasNext()) {
            return K.a;
        }
        Object next = it2.next();
        if (!it2.hasNext()) {
            return A.b(next);
        }
        ArrayList arrayList = new ArrayList();
        arrayList.add(next);
        while (it2.hasNext()) {
            arrayList.add(it2.next());
        }
        return arrayList;
    }

    public static ArrayList k(f fVar) {
        Intrinsics.checkNotNullParameter(fVar, "<this>");
        ArrayList destination = new ArrayList();
        Intrinsics.checkNotNullParameter(fVar, "<this>");
        Intrinsics.checkNotNullParameter(destination, "destination");
        e eVar = new e(fVar);
        while (eVar.hasNext()) {
            destination.add(eVar.next());
        }
        return destination;
    }
}
