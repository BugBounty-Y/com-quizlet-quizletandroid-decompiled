package com.squareup.moshi;

import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import java.lang.reflect.Array;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;

/* loaded from: classes3.dex */
public abstract class H {
    public static final com.quizlet.remote.model.selectedterm.c a = new com.quizlet.remote.model.selectedterm.c(6);
    public static final com.quizlet.remote.util.c b = new com.quizlet.remote.util.c(2);
    public static final com.quizlet.remote.util.c c = new com.quizlet.remote.util.c(3);
    public static final com.quizlet.remote.util.c d = new com.quizlet.remote.util.c(4);
    public static final com.quizlet.remote.util.c e = new com.quizlet.remote.util.c(5);
    public static final com.quizlet.remote.util.c f = new com.quizlet.remote.util.c(6);
    public static final com.quizlet.remote.util.c g = new com.quizlet.remote.util.c(7);
    public static final com.quizlet.remote.util.c h = new com.quizlet.remote.util.c(8);
    public static final com.quizlet.remote.util.c i = new com.quizlet.remote.util.c(9);
    public static final com.quizlet.remote.util.c j = new com.quizlet.remote.util.c(1);

    public static Type a(Type type) {
        if (!Collection.class.isAssignableFrom(Collection.class)) {
            throw new IllegalArgumentException();
        }
        Type typeG = com.squareup.moshi.internal.b.g(type, Collection.class, com.squareup.moshi.internal.b.c(type, Collection.class, Collection.class), new LinkedHashSet());
        if (typeG instanceof WildcardType) {
            typeG = ((WildcardType) typeG).getUpperBounds()[0];
        }
        return typeG instanceof ParameterizedType ? ((ParameterizedType) typeG).getActualTypeArguments()[0] : Object.class;
    }

    public static boolean b(Type type, Type type2) {
        if (type == type2) {
            return true;
        }
        if (type instanceof Class) {
            return type2 instanceof GenericArrayType ? b(((Class) type).getComponentType(), ((GenericArrayType) type2).getGenericComponentType()) : type.equals(type2);
        }
        if (type instanceof ParameterizedType) {
            if (!(type2 instanceof ParameterizedType)) {
                return false;
            }
            ParameterizedType parameterizedType = (ParameterizedType) type;
            ParameterizedType parameterizedType2 = (ParameterizedType) type2;
            return b(parameterizedType.getOwnerType(), parameterizedType2.getOwnerType()) && parameterizedType.getRawType().equals(parameterizedType2.getRawType()) && Arrays.equals(parameterizedType instanceof Util$ParameterizedTypeImpl ? ((Util$ParameterizedTypeImpl) parameterizedType).c : parameterizedType.getActualTypeArguments(), parameterizedType2 instanceof Util$ParameterizedTypeImpl ? ((Util$ParameterizedTypeImpl) parameterizedType2).c : parameterizedType2.getActualTypeArguments());
        }
        if (type instanceof GenericArrayType) {
            if (type2 instanceof Class) {
                return b(((Class) type2).getComponentType(), ((GenericArrayType) type).getGenericComponentType());
            }
            if (type2 instanceof GenericArrayType) {
                return b(((GenericArrayType) type).getGenericComponentType(), ((GenericArrayType) type2).getGenericComponentType());
            }
            return false;
        }
        if (type instanceof WildcardType) {
            if (!(type2 instanceof WildcardType)) {
                return false;
            }
            WildcardType wildcardType = (WildcardType) type;
            WildcardType wildcardType2 = (WildcardType) type2;
            return Arrays.equals(wildcardType.getUpperBounds(), wildcardType2.getUpperBounds()) && Arrays.equals(wildcardType.getLowerBounds(), wildcardType2.getLowerBounds());
        }
        if (!(type instanceof TypeVariable) || !(type2 instanceof TypeVariable)) {
            return false;
        }
        TypeVariable typeVariable = (TypeVariable) type;
        TypeVariable typeVariable2 = (TypeVariable) type2;
        return typeVariable.getGenericDeclaration() == typeVariable2.getGenericDeclaration() && typeVariable.getName().equals(typeVariable2.getName());
    }

    public static String c(int i2, int[] iArr, String[] strArr, int[] iArr2) {
        StringBuilder sb = new StringBuilder("$");
        for (int i3 = 0; i3 < i2; i3++) {
            int i4 = iArr[i3];
            if (i4 == 1 || i4 == 2) {
                sb.append('[');
                sb.append(iArr2[i3]);
                sb.append(']');
            } else if (i4 == 3 || i4 == 4 || i4 == 5) {
                sb.append('.');
                String str = strArr[i3];
                if (str != null) {
                    sb.append(str);
                }
            }
        }
        return sb.toString();
    }

    public static Class d(Type type) {
        if (type instanceof Class) {
            return (Class) type;
        }
        if (type instanceof ParameterizedType) {
            return (Class) ((ParameterizedType) type).getRawType();
        }
        if (type instanceof GenericArrayType) {
            return Array.newInstance((Class<?>) d(((GenericArrayType) type).getGenericComponentType()), 0).getClass();
        }
        if (type instanceof TypeVariable) {
            return Object.class;
        }
        if (type instanceof WildcardType) {
            return d(((WildcardType) type).getUpperBounds()[0]);
        }
        throw new IllegalArgumentException("Expected a Class, ParameterizedType, or GenericArrayType, but <" + type + "> is of type " + (type == null ? "null" : type.getClass().getName()));
    }

    public static Util$ParameterizedTypeImpl f(Class cls, Type... typeArr) {
        if (typeArr.length != 0) {
            return new Util$ParameterizedTypeImpl(null, cls, typeArr);
        }
        throw new IllegalArgumentException(androidx.compose.ui.node.B.d(cls, "Missing type arguments for "));
    }

    public static int g(p pVar, String str, int i2, int i3) {
        int iR = pVar.r();
        if (iR >= i2 && iR <= i3) {
            return iR;
        }
        throw new JsonDataException("Expected " + str + " but was " + iR + " at path " + pVar.j());
    }

    public abstract Object e();
}
