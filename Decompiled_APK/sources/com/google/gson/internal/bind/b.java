package com.google.gson.internal.bind;

import com.google.gson.JsonSyntaxException;
import com.google.gson.q;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.security.AccessController;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;

/* loaded from: classes2.dex */
public final class b extends q {
    public static final a d = new a(0);
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public b(com.google.gson.k kVar, q qVar, Class cls) {
        this.a = 0;
        this.b = new d(kVar, qVar, cls);
        this.c = cls;
    }

    @Override // com.google.gson.q
    public final Object a(com.google.gson.stream.a aVar) throws IllegalAccessException, IOException, ArrayIndexOutOfBoundsException, IllegalArgumentException, NegativeArraySizeException {
        switch (this.a) {
            case 0:
                if (aVar.l0() == 9) {
                    aVar.a0();
                    return null;
                }
                ArrayList arrayList = new ArrayList();
                aVar.a();
                while (aVar.q()) {
                    arrayList.add(((q) ((d) this.b).b).a(aVar));
                }
                aVar.j();
                int size = arrayList.size();
                Object objNewInstance = Array.newInstance((Class<?>) this.c, size);
                for (int i = 0; i < size; i++) {
                    Array.set(objNewInstance, i, arrayList.get(i));
                }
                return objNewInstance;
            case 1:
                if (aVar.l0() == 9) {
                    aVar.a0();
                    return null;
                }
                Collection collection = (Collection) ((com.google.gson.internal.n) this.c).E();
                aVar.a();
                while (aVar.q()) {
                    collection.add(((q) ((d) this.b).b).a(aVar));
                }
                aVar.j();
                return collection;
            case 2:
                if (aVar.l0() == 9) {
                    aVar.a0();
                    return null;
                }
                Object objE = ((com.google.gson.internal.n) this.c).E();
                try {
                    aVar.d();
                    while (aVar.q()) {
                        i iVar = (i) ((LinkedHashMap) this.b).get(aVar.Q());
                        if (iVar == null || !iVar.b) {
                            aVar.q0();
                        } else {
                            Object objA = iVar.d.a(aVar);
                            if (objA != null || !iVar.e) {
                                iVar.c.set(objE, objA);
                            }
                        }
                    }
                    aVar.l();
                    return objE;
                } catch (IllegalAccessException e) {
                    throw new AssertionError(e);
                } catch (IllegalStateException e2) {
                    throw new JsonSyntaxException(e2);
                }
            case 3:
                Object objA2 = ((m) this.b).c.a(aVar);
                if (objA2 != null) {
                    Class cls = (Class) this.c;
                    if (!cls.isInstance(objA2)) {
                        throw new JsonSyntaxException("Expected a " + cls.getName() + " but was " + objA2.getClass().getName());
                    }
                }
                return objA2;
            default:
                if (aVar.l0() != 9) {
                    return (Enum) ((HashMap) this.c).get(aVar.d0());
                }
                aVar.a0();
                return null;
        }
    }

    public b(com.google.gson.k kVar, Type type, q qVar, com.google.gson.internal.n nVar) {
        this.a = 1;
        this.b = new d(kVar, qVar, type);
        this.c = nVar;
    }

    public b(com.google.gson.internal.n nVar, LinkedHashMap linkedHashMap) {
        this.a = 2;
        this.c = nVar;
        this.b = linkedHashMap;
    }

    public b(m mVar, Class cls) {
        this.a = 3;
        this.b = mVar;
        this.c = cls;
    }

    public b(Class cls) {
        this.a = 4;
        this.c = new HashMap();
        this.b = new HashMap();
        try {
            for (Field field : cls.getDeclaredFields()) {
                if (field.isEnumConstant()) {
                    AccessController.doPrivileged(new o(field));
                    Enum r4 = (Enum) field.get(null);
                    String strName = r4.name();
                    com.google.gson.annotations.b bVar = (com.google.gson.annotations.b) field.getAnnotation(com.google.gson.annotations.b.class);
                    if (bVar != null) {
                        strName = bVar.value();
                        for (String str : bVar.alternate()) {
                            ((HashMap) this.c).put(str, r4);
                        }
                    }
                    ((HashMap) this.c).put(strName, r4);
                    ((HashMap) this.b).put(r4, strName);
                }
            }
        } catch (IllegalAccessException e) {
            throw new AssertionError(e);
        }
    }
}
