package androidx.compose.runtime.saveable;

import androidx.collection.I;
import androidx.collection.S;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.text.CharsKt;

/* loaded from: classes.dex */
public final class j implements i {
    public final r a;
    public final I b;
    public I c;

    /* JADX WARN: Multi-variable type inference failed */
    public j(Map from, Function1 function1) {
        I i;
        this.a = (r) function1;
        if (from == null || from.isEmpty()) {
            i = null;
        } else {
            i = new I(from.size());
            Intrinsics.checkNotNullParameter(from, "from");
            for (Map.Entry entry : from.entrySet()) {
                i.j(entry.getKey(), entry.getValue());
            }
        }
        this.b = i;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // androidx.compose.runtime.saveable.i
    public final boolean a(Object obj) {
        return ((Boolean) this.a.invoke(obj)).booleanValue();
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x0090  */
    @Override // androidx.compose.runtime.saveable.i
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.Map b() {
        /*
            Method dump skipped, instructions count: 357
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.saveable.j.b():java.util.Map");
    }

    @Override // androidx.compose.runtime.saveable.i
    public final Object c(String str) {
        I i = this.b;
        List list = i != null ? (List) i.h(str) : null;
        if (list == null || list.isEmpty()) {
            return null;
        }
        if (list.size() > 1 && i != null) {
            List listSubList = list.subList(1, list.size());
            int iE = i.e(str);
            if (iE < 0) {
                iE = ~iE;
            }
            Object[] objArr = i.c;
            Object obj = objArr[iE];
            i.b[iE] = str;
            objArr[iE] = listSubList;
        }
        return list.get(0);
    }

    @Override // androidx.compose.runtime.saveable.i
    public final h d(String str, Function0 function0) {
        int length = str.length();
        for (int i = 0; i < length; i++) {
            if (!CharsKt.b(str.charAt(i))) {
                I i2 = this.c;
                if (i2 == null) {
                    long[] jArr = S.a;
                    i2 = new I();
                    this.c = i2;
                }
                Object objF = i2.f(str);
                if (objF == null) {
                    objF = new ArrayList();
                    i2.j(str, objF);
                }
                ((List) objF).add(function0);
                return new com.quizlet.data.repository.course.membership.c(i2, str, function0);
            }
        }
        throw new IllegalArgumentException("Registered key is empty or blank");
    }
}
