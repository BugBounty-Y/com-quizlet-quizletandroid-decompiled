package com.google.gson.internal.bind;

import androidx.work.impl.model.v;
import com.google.gson.q;
import com.google.gson.r;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.WildcardType;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/* loaded from: classes2.dex */
public final class c implements r {
    public final /* synthetic */ int a;
    public final v b;

    public /* synthetic */ c(v vVar, int i) {
        this.a = i;
        this.b = vVar;
    }

    public static q a(v vVar, com.google.gson.k kVar, TypeToken typeToken, com.google.gson.annotations.a aVar) {
        q lVar;
        Object objE = vVar.c(new TypeToken(aVar.value())).E();
        if (objE instanceof q) {
            lVar = (q) objE;
        } else if (objE instanceof r) {
            lVar = ((r) objE).b(kVar, typeToken);
        } else {
            if (!(objE instanceof com.auth0.android.jwt.c)) {
                throw new IllegalArgumentException("Invalid attempt to bind an instance of " + objE.getClass().getName() + " as a @JsonAdapter for " + com.google.gson.internal.d.k(typeToken.b) + ". @JsonAdapter value must be a TypeAdapter, TypeAdapterFactory, JsonSerializer or JsonDeserializer.");
            }
            lVar = new l(objE != null ? (com.auth0.android.jwt.c) objE : null, kVar, typeToken, null);
        }
        return (lVar == null || !aVar.nullSafe()) ? lVar : new com.google.gson.i(lVar, 2);
    }

    @Override // com.google.gson.r
    public final q b(com.google.gson.k kVar, TypeToken typeToken) throws NoSuchMethodException, SecurityException {
        Class cls;
        Type[] actualTypeArguments;
        cls = Object.class;
        v vVar = this.b;
        switch (this.a) {
            case 0:
                Class cls2 = typeToken.a;
                if (!Collection.class.isAssignableFrom(cls2)) {
                    return null;
                }
                Type type = typeToken.b;
                if (type instanceof WildcardType) {
                    type = ((WildcardType) type).getUpperBounds()[0];
                }
                com.google.gson.internal.d.c(Collection.class.isAssignableFrom(cls2));
                Type typeJ = com.google.gson.internal.d.j(type, cls2, com.google.gson.internal.d.g(type, cls2, Collection.class), new HashMap());
                if (typeJ instanceof WildcardType) {
                    typeJ = ((WildcardType) typeJ).getUpperBounds()[0];
                }
                cls = typeJ instanceof ParameterizedType ? ((ParameterizedType) typeJ).getActualTypeArguments()[0] : Object.class;
                return new b(kVar, cls, kVar.b(new TypeToken(cls)), vVar.c(typeToken));
            case 1:
                com.google.gson.annotations.a aVar = (com.google.gson.annotations.a) typeToken.a.getAnnotation(com.google.gson.annotations.a.class);
                if (aVar == null) {
                    return null;
                }
                return a(vVar, kVar, typeToken, aVar);
            default:
                if (!Map.class.isAssignableFrom(typeToken.a)) {
                    return null;
                }
                Type type2 = typeToken.b;
                Class clsH = com.google.gson.internal.d.h(type2);
                if (type2 == Properties.class) {
                    actualTypeArguments = new Type[]{String.class, String.class};
                } else {
                    if (type2 instanceof WildcardType) {
                        type2 = ((WildcardType) type2).getUpperBounds()[0];
                    }
                    com.google.gson.internal.d.c(Map.class.isAssignableFrom(clsH));
                    Type typeJ2 = com.google.gson.internal.d.j(type2, clsH, com.google.gson.internal.d.g(type2, clsH, Map.class), new HashMap());
                    actualTypeArguments = typeJ2 instanceof ParameterizedType ? ((ParameterizedType) typeJ2).getActualTypeArguments() : new Type[]{cls, cls};
                }
                Type type3 = actualTypeArguments[0];
                q qVarB = (type3 == Boolean.TYPE || type3 == Boolean.class) ? p.c : kVar.b(new TypeToken(type3));
                q qVarB2 = kVar.b(new TypeToken(actualTypeArguments[1]));
                com.google.gson.internal.n nVarC = vVar.c(typeToken);
                Type[] typeArr = actualTypeArguments;
                return new f(this, kVar, typeArr[0], qVarB, typeArr[1], qVarB2, nVarC);
        }
    }
}
