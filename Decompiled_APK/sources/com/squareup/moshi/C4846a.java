package com.squareup.moshi;

import com.j256.ormlite.stmt.query.SimpleComparison;
import java.lang.reflect.Array;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;

/* renamed from: com.squareup.moshi.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4846a extends l {
    public static final com.quizlet.remote.model.selectedterm.c d = new com.quizlet.remote.model.selectedterm.c(1);
    public static final com.quizlet.remote.model.selectedterm.c e = new com.quizlet.remote.model.selectedterm.c(4);
    public final /* synthetic */ int a = 1;
    public final l b;
    public final Object c;

    public C4846a(D d2, Type type, Type type2) {
        d2.getClass();
        Set set = com.squareup.moshi.internal.b.a;
        this.b = d2.a(type, set, null);
        this.c = d2.a(type2, set, null);
    }

    @Override // com.squareup.moshi.l
    public final Object a(p pVar) throws ArrayIndexOutOfBoundsException, IllegalArgumentException, NegativeArraySizeException {
        switch (this.a) {
            case 0:
                ArrayList arrayList = new ArrayList();
                pVar.a();
                while (pVar.l()) {
                    arrayList.add(this.b.a(pVar));
                }
                pVar.f();
                Object objNewInstance = Array.newInstance((Class<?>) this.c, arrayList.size());
                for (int i = 0; i < arrayList.size(); i++) {
                    Array.set(objNewInstance, i, arrayList.get(i));
                }
                return objNewInstance;
            default:
                A a = new A();
                pVar.d();
                while (pVar.l()) {
                    pVar.a0();
                    Object objA = this.b.a(pVar);
                    Object objA2 = ((l) this.c).a(pVar);
                    Object objPut = a.put(objA, objA2);
                    if (objPut != null) {
                        throw new JsonDataException("Map key '" + objA + "' has multiple values at path " + pVar.j() + ": " + objPut + " and " + objA2);
                    }
                }
                pVar.i();
                return a;
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w wVar, Object obj) {
        switch (this.a) {
            case 0:
                wVar.a();
                int length = Array.getLength(obj);
                for (int i = 0; i < length; i++) {
                    this.b.g(wVar, Array.get(obj, i));
                }
                ((s) wVar).Q(1, ']', 2);
                return;
            default:
                wVar.d();
                for (Map.Entry entry : ((Map) obj).entrySet()) {
                    if (entry.getKey() == null) {
                        throw new JsonDataException("Map key is null at " + wVar.i());
                    }
                    int iQ = wVar.q();
                    if (iQ != 5 && iQ != 3) {
                        throw new IllegalStateException("Nesting problem.");
                    }
                    wVar.f = true;
                    this.b.g(wVar, entry.getKey());
                    ((l) this.c).g(wVar, entry.getValue());
                }
                wVar.f();
                return;
        }
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                return this.b + ".array()";
            default:
                return "JsonAdapter(" + this.b + SimpleComparison.EQUAL_TO_OPERATION + ((l) this.c) + ")";
        }
    }

    public C4846a(Class cls, l lVar) {
        this.c = cls;
        this.b = lVar;
    }
}
