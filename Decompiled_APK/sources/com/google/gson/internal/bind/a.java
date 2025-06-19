package com.google.gson.internal.bind;

import com.google.gson.q;
import com.google.gson.r;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Type;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.Date;

/* loaded from: classes2.dex */
public final class a implements r {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // com.google.gson.r
    public final q b(com.google.gson.k kVar, TypeToken typeToken) {
        switch (this.a) {
            case 0:
                Type type = typeToken.b;
                boolean z = type instanceof GenericArrayType;
                if (!z && (!(type instanceof Class) || !((Class) type).isArray())) {
                    return null;
                }
                Type genericComponentType = z ? ((GenericArrayType) type).getGenericComponentType() : ((Class) type).getComponentType();
                return new b(kVar, kVar.b(new TypeToken(genericComponentType)), com.google.gson.internal.d.h(genericComponentType));
            case 1:
                if (typeToken.a == Date.class) {
                    return new d();
                }
                return null;
            case 2:
                if (typeToken.a == Object.class) {
                    return new h(kVar);
                }
                return null;
            case 3:
                Class superclass = typeToken.a;
                if (!Enum.class.isAssignableFrom(superclass) || superclass == Enum.class) {
                    return null;
                }
                if (!superclass.isEnum()) {
                    superclass = superclass.getSuperclass();
                }
                return new b(superclass);
            case 4:
                if (typeToken.a == java.sql.Date.class) {
                    return new com.google.gson.internal.sql.a(0);
                }
                return null;
            case 5:
                if (typeToken.a == Time.class) {
                    return new com.google.gson.internal.sql.a(1);
                }
                return null;
            default:
                if (typeToken.a != Timestamp.class) {
                    return null;
                }
                kVar.getClass();
                return new com.google.gson.internal.sql.a(kVar.b(new TypeToken(Date.class)));
        }
    }
}
