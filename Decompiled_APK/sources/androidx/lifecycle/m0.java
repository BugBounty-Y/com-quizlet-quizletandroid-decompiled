package androidx.lifecycle;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m0 {
    public final LinkedHashMap a;
    public final com.quizlet.data.repository.studysetwithcreatorinclass.g b;

    public m0(kotlin.collections.builders.h initialState) {
        Intrinsics.checkNotNullParameter(initialState, "initialState");
        this.a = new LinkedHashMap();
        this.b = new com.quizlet.data.repository.studysetwithcreatorinclass.g(initialState);
    }

    public final Object a(String key) {
        Object value;
        Intrinsics.checkNotNullParameter(key, "key");
        com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = this.b;
        gVar.getClass();
        LinkedHashMap linkedHashMap = (LinkedHashMap) gVar.b;
        Intrinsics.checkNotNullParameter(key, "key");
        try {
            kotlinx.coroutines.flow.X x = (kotlinx.coroutines.flow.X) ((LinkedHashMap) gVar.e).get(key);
            if (x != null && (value = ((kotlinx.coroutines.flow.s0) x).getValue()) != null) {
                return value;
            }
            return linkedHashMap.get(key);
        } catch (ClassCastException unused) {
            Intrinsics.checkNotNullParameter(key, "key");
            linkedHashMap.remove(key);
            ((LinkedHashMap) gVar.d).remove(key);
            return null;
        }
    }

    public final Object b(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = this.b;
        gVar.getClass();
        Intrinsics.checkNotNullParameter(key, "key");
        Object objRemove = ((LinkedHashMap) gVar.b).remove(key);
        ((LinkedHashMap) gVar.d).remove(key);
        if (this.a.remove(key) == null) {
            return objRemove;
        }
        throw new ClassCastException();
    }

    public final void c(Object obj, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        if (obj != null) {
            ArrayList arrayList = androidx.lifecycle.internal.a.a;
            if (arrayList == null || !arrayList.isEmpty()) {
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    if (((Class) it2.next()).isInstance(obj)) {
                    }
                }
            }
            throw new IllegalArgumentException(("Can't put value with type " + obj.getClass() + " into saved state").toString());
        }
        ArrayList arrayList2 = androidx.lifecycle.internal.a.a;
        Object obj2 = this.a.get(key);
        Y y = obj2 instanceof Y ? (Y) obj2 : null;
        if (y != null) {
            y.l(obj);
        }
        this.b.s(obj, key);
    }

    public m0() {
        this.a = new LinkedHashMap();
        this.b = new com.quizlet.data.repository.studysetwithcreatorinclass.g(kotlin.collections.V.c());
    }
}
