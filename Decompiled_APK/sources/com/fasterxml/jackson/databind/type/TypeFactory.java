package com.fasterxml.jackson.databind.type;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.util.ClassUtil;
import com.fasterxml.jackson.databind.util.LRUMap;
import com.fasterxml.jackson.databind.util.LookupCache;
import java.io.Serializable;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.BaseStream;
import java.util.stream.DoubleStream;
import java.util.stream.IntStream;
import java.util.stream.LongStream;
import java.util.stream.Stream;

/* loaded from: classes.dex */
public class TypeFactory implements Serializable {
    private static final Class<?> CLS_BOOL;
    private static final Class<?> CLS_DOUBLE;
    private static final Class<?> CLS_INT;
    private static final Class<?> CLS_LONG;
    protected static final SimpleType CORE_TYPE_BOOL;
    protected static final SimpleType CORE_TYPE_COMPARABLE;
    protected static final SimpleType CORE_TYPE_DOUBLE;
    protected static final SimpleType CORE_TYPE_ENUM;
    protected static final SimpleType CORE_TYPE_INT;
    protected static final SimpleType CORE_TYPE_JSON_NODE;
    protected static final SimpleType CORE_TYPE_LONG;
    protected static final SimpleType CORE_TYPE_OBJECT;
    protected static final SimpleType CORE_TYPE_STRING;
    protected final ClassLoader _classLoader;
    protected final TypeModifier[] _modifiers;
    protected final TypeParser _parser;
    protected final LookupCache<Object, JavaType> _typeCache;
    private static final JavaType[] NO_TYPES = new JavaType[0];
    protected static final TypeFactory instance = new TypeFactory();
    protected static final TypeBindings EMPTY_BINDINGS = TypeBindings.emptyBindings();
    private static final Class<?> CLS_STRING = String.class;
    private static final Class<?> CLS_OBJECT = Object.class;
    private static final Class<?> CLS_COMPARABLE = Comparable.class;
    private static final Class<?> CLS_ENUM = Enum.class;
    private static final Class<?> CLS_JSON_NODE = JsonNode.class;

    static {
        Class<?> cls = Boolean.TYPE;
        CLS_BOOL = cls;
        Class<?> cls2 = Double.TYPE;
        CLS_DOUBLE = cls2;
        Class<?> cls3 = Integer.TYPE;
        CLS_INT = cls3;
        Class<?> cls4 = Long.TYPE;
        CLS_LONG = cls4;
        CORE_TYPE_BOOL = new SimpleType(cls);
        CORE_TYPE_DOUBLE = new SimpleType(cls2);
        CORE_TYPE_INT = new SimpleType(cls3);
        CORE_TYPE_LONG = new SimpleType(cls4);
        CORE_TYPE_STRING = new SimpleType(String.class);
        CORE_TYPE_OBJECT = new SimpleType(Object.class);
        CORE_TYPE_COMPARABLE = new SimpleType(Comparable.class);
        CORE_TYPE_ENUM = new SimpleType(Enum.class);
        CORE_TYPE_JSON_NODE = new SimpleType(JsonNode.class);
    }

    private TypeFactory() {
        this(new LRUMap(16, 200));
    }

    private TypeBindings _bindingsForSubtype(JavaType javaType, int i, Class<?> cls, boolean z) throws IllegalArgumentException {
        PlaceholderForType[] placeholderForTypeArr = new PlaceholderForType[i];
        for (int i2 = 0; i2 < i; i2++) {
            placeholderForTypeArr[i2] = new PlaceholderForType(i2);
        }
        JavaType javaTypeFindSuperType = _fromClass(null, cls, TypeBindings.create(cls, placeholderForTypeArr)).findSuperType(javaType.getRawClass());
        if (javaTypeFindSuperType == null) {
            throw new IllegalArgumentException(a.m("Internal error: unable to locate supertype (", javaType.getRawClass().getName(), ") from resolved subtype ", cls.getName()));
        }
        String str_resolveTypePlaceholders = _resolveTypePlaceholders(javaType, javaTypeFindSuperType);
        if (str_resolveTypePlaceholders != null && !z) {
            throw new IllegalArgumentException("Failed to specialize base type " + javaType.toCanonical() + " as " + cls.getName() + ", problem: " + str_resolveTypePlaceholders);
        }
        JavaType[] javaTypeArr = new JavaType[i];
        for (int i3 = 0; i3 < i; i3++) {
            JavaType javaTypeActualType = placeholderForTypeArr[i3].actualType();
            if (javaTypeActualType == null) {
                javaTypeActualType = unknownType();
            }
            javaTypeArr[i3] = javaTypeActualType;
        }
        return TypeBindings.create(cls, javaTypeArr);
    }

    private JavaType _collectionType(Class<?> cls, TypeBindings typeBindings, JavaType javaType, JavaType[] javaTypeArr) {
        JavaType javaType_unknownType;
        List<JavaType> typeParameters = typeBindings.getTypeParameters();
        if (typeParameters.isEmpty()) {
            javaType_unknownType = _unknownType();
        } else {
            if (typeParameters.size() != 1) {
                throw new IllegalArgumentException(assistantMode.refactored.a.i(cls, new StringBuilder("Strange Collection type "), ": cannot determine type parameters"));
            }
            javaType_unknownType = typeParameters.get(0);
        }
        return CollectionType.construct(cls, typeBindings, javaType, javaTypeArr, javaType_unknownType);
    }

    private JavaType _iterationType(Class<?> cls, TypeBindings typeBindings, JavaType javaType, JavaType[] javaTypeArr) {
        JavaType javaType_unknownType;
        List<JavaType> typeParameters = typeBindings.getTypeParameters();
        if (typeParameters.isEmpty()) {
            javaType_unknownType = _unknownType();
        } else {
            if (typeParameters.size() != 1) {
                throw new IllegalArgumentException(assistantMode.refactored.a.i(cls, new StringBuilder("Strange Iteration type "), ": cannot determine type parameters"));
            }
            javaType_unknownType = typeParameters.get(0);
        }
        return _iterationType(cls, typeBindings, javaType, javaTypeArr, javaType_unknownType);
    }

    private JavaType _mapType(Class<?> cls, TypeBindings typeBindings, JavaType javaType, JavaType[] javaTypeArr) {
        JavaType javaType_unknownType;
        TypeBindings typeBindings2;
        JavaType javaType2;
        JavaType[] javaTypeArr2;
        JavaType javaType3;
        JavaType javaType4;
        Class<?> cls2;
        if (cls == Properties.class) {
            javaType_unknownType = CORE_TYPE_STRING;
        } else {
            List<JavaType> typeParameters = typeBindings.getTypeParameters();
            int size = typeParameters.size();
            if (size != 0) {
                if (size != 2) {
                    throw new IllegalArgumentException(String.format("Strange Map type %s with %d type parameter%s (%s), can not resolve", ClassUtil.nameOf(cls), Integer.valueOf(size), size == 1 ? "" : "s", typeBindings));
                }
                JavaType javaType5 = typeParameters.get(0);
                typeBindings2 = typeBindings;
                javaType2 = javaType;
                javaTypeArr2 = javaTypeArr;
                javaType3 = typeParameters.get(1);
                javaType4 = javaType5;
                cls2 = cls;
                return MapType.construct(cls2, typeBindings2, javaType2, javaTypeArr2, javaType4, javaType3);
            }
            javaType_unknownType = _unknownType();
        }
        cls2 = cls;
        typeBindings2 = typeBindings;
        javaType2 = javaType;
        javaTypeArr2 = javaTypeArr;
        javaType4 = javaType_unknownType;
        javaType3 = javaType4;
        return MapType.construct(cls2, typeBindings2, javaType2, javaTypeArr2, javaType4, javaType3);
    }

    private JavaType _referenceType(Class<?> cls, TypeBindings typeBindings, JavaType javaType, JavaType[] javaTypeArr) {
        JavaType javaType_unknownType;
        List<JavaType> typeParameters = typeBindings.getTypeParameters();
        if (typeParameters.isEmpty()) {
            javaType_unknownType = _unknownType();
        } else {
            if (typeParameters.size() != 1) {
                throw new IllegalArgumentException(assistantMode.refactored.a.i(cls, new StringBuilder("Strange Reference type "), ": cannot determine type parameters"));
            }
            javaType_unknownType = typeParameters.get(0);
        }
        return ReferenceType.construct(cls, typeBindings, javaType, javaTypeArr, javaType_unknownType);
    }

    private String _resolveTypePlaceholders(JavaType javaType, JavaType javaType2) throws IllegalArgumentException {
        List<JavaType> typeParameters = javaType.getBindings().getTypeParameters();
        List<JavaType> typeParameters2 = javaType2.getBindings().getTypeParameters();
        int size = typeParameters2.size();
        int size2 = typeParameters.size();
        int i = 0;
        while (i < size2) {
            JavaType javaType3 = typeParameters.get(i);
            JavaType javaTypeUnknownType = i < size ? typeParameters2.get(i) : unknownType();
            if (!_verifyAndResolvePlaceholders(javaType3, javaTypeUnknownType) && !javaType3.hasRawClass(Object.class) && ((i != 0 || !javaType.isMapLikeType() || !javaTypeUnknownType.hasRawClass(Object.class)) && (!javaType3.isInterface() || !javaType3.isTypeOrSuperTypeOf(javaTypeUnknownType.getRawClass())))) {
                return String.format("Type parameter #%d/%d differs; can not specialize %s with %s", Integer.valueOf(i + 1), Integer.valueOf(size2), javaType3.toCanonical(), javaTypeUnknownType.toCanonical());
            }
            i++;
        }
        return null;
    }

    private boolean _verifyAndResolvePlaceholders(JavaType javaType, JavaType javaType2) {
        if (javaType2 instanceof PlaceholderForType) {
            ((PlaceholderForType) javaType2).actualType(javaType);
            return true;
        }
        if (javaType.getRawClass() != javaType2.getRawClass()) {
            return false;
        }
        List<JavaType> typeParameters = javaType.getBindings().getTypeParameters();
        List<JavaType> typeParameters2 = javaType2.getBindings().getTypeParameters();
        int size = typeParameters.size();
        for (int i = 0; i < size; i++) {
            if (!_verifyAndResolvePlaceholders(typeParameters.get(i), typeParameters2.get(i))) {
                return false;
            }
        }
        return true;
    }

    public static TypeFactory defaultInstance() {
        return instance;
    }

    public static JavaType unknownType() {
        return CORE_TYPE_OBJECT;
    }

    public JavaType _applyModifiers(Type type, JavaType javaType) {
        if (this._modifiers == null) {
            return javaType;
        }
        javaType.getBindings();
        TypeModifier[] typeModifierArr = this._modifiers;
        if (typeModifierArr.length <= 0) {
            return javaType;
        }
        TypeModifier typeModifier = typeModifierArr[0];
        throw null;
    }

    public JavaType _constructSimple(Class<?> cls, TypeBindings typeBindings, JavaType javaType, JavaType[] javaTypeArr) {
        JavaType javaType_findWellKnownSimple;
        return (!typeBindings.isEmpty() || (javaType_findWellKnownSimple = _findWellKnownSimple(cls)) == null) ? _newSimpleType(cls, typeBindings, javaType, javaTypeArr) : javaType_findWellKnownSimple;
    }

    public Class<?> _findPrimitive(String str) {
        if ("int".equals(str)) {
            return Integer.TYPE;
        }
        if ("long".equals(str)) {
            return Long.TYPE;
        }
        if ("float".equals(str)) {
            return Float.TYPE;
        }
        if ("double".equals(str)) {
            return Double.TYPE;
        }
        if ("boolean".equals(str)) {
            return Boolean.TYPE;
        }
        if ("byte".equals(str)) {
            return Byte.TYPE;
        }
        if ("char".equals(str)) {
            return Character.TYPE;
        }
        if ("short".equals(str)) {
            return Short.TYPE;
        }
        if ("void".equals(str)) {
            return Void.TYPE;
        }
        return null;
    }

    public JavaType _findWellKnownSimple(Class<?> cls) {
        if (!cls.isPrimitive()) {
            if (cls == CLS_STRING) {
                return CORE_TYPE_STRING;
            }
            if (cls == CLS_OBJECT) {
                return CORE_TYPE_OBJECT;
            }
            if (cls == CLS_JSON_NODE) {
                return CORE_TYPE_JSON_NODE;
            }
            return null;
        }
        if (cls == CLS_BOOL) {
            return CORE_TYPE_BOOL;
        }
        if (cls == CLS_INT) {
            return CORE_TYPE_INT;
        }
        if (cls == CLS_LONG) {
            return CORE_TYPE_LONG;
        }
        if (cls == CLS_DOUBLE) {
            return CORE_TYPE_DOUBLE;
        }
        return null;
    }

    public JavaType _fromAny(ClassStack classStack, Type type, TypeBindings typeBindings) {
        JavaType javaType_fromWildcard;
        if (type instanceof Class) {
            javaType_fromWildcard = _fromClass(classStack, (Class) type, EMPTY_BINDINGS);
        } else if (type instanceof ParameterizedType) {
            javaType_fromWildcard = _fromParamType(classStack, (ParameterizedType) type, typeBindings);
        } else {
            if (type instanceof JavaType) {
                return (JavaType) type;
            }
            if (type instanceof GenericArrayType) {
                javaType_fromWildcard = _fromArrayType(classStack, (GenericArrayType) type, typeBindings);
            } else if (type instanceof TypeVariable) {
                javaType_fromWildcard = _fromVariable(classStack, (TypeVariable) type, typeBindings);
            } else {
                if (!(type instanceof WildcardType)) {
                    StringBuilder sb = new StringBuilder("Unrecognized Type: ");
                    sb.append(type == null ? "[null]" : type.toString());
                    throw new IllegalArgumentException(sb.toString());
                }
                javaType_fromWildcard = _fromWildcard(classStack, (WildcardType) type, typeBindings);
            }
        }
        return _applyModifiers(type, javaType_fromWildcard);
    }

    public JavaType _fromArrayType(ClassStack classStack, GenericArrayType genericArrayType, TypeBindings typeBindings) {
        return ArrayType.construct(_fromAny(classStack, genericArrayType.getGenericComponentType(), typeBindings), typeBindings);
    }

    public JavaType _fromClass(ClassStack classStack, Class<?> cls, TypeBindings typeBindings) {
        ClassStack classStackChild;
        JavaType[] javaTypeArr_resolveSuperInterfaces;
        Class<?> cls2;
        TypeBindings typeBindings2;
        TypeFactory typeFactory;
        JavaType javaType_fromWellKnownClass;
        JavaType javaType_findWellKnownSimple = _findWellKnownSimple(cls);
        if (javaType_findWellKnownSimple != null) {
            return javaType_findWellKnownSimple;
        }
        Object objAsKey = (typeBindings == null || typeBindings.isEmpty()) ? cls : typeBindings.asKey(cls);
        JavaType javaType_resolveSuperClass = null;
        JavaType javaTypeRefine = objAsKey == null ? null : this._typeCache.get(objAsKey);
        if (javaTypeRefine != null) {
            return javaTypeRefine;
        }
        if (classStack == null) {
            classStackChild = new ClassStack(cls);
        } else {
            ClassStack classStackFind = classStack.find(cls);
            if (classStackFind != null) {
                ResolvedRecursiveType resolvedRecursiveType = new ResolvedRecursiveType(cls, EMPTY_BINDINGS);
                classStackFind.addSelfReference(resolvedRecursiveType);
                return resolvedRecursiveType;
            }
            classStackChild = classStack.child(cls);
        }
        ClassStack classStack2 = classStackChild;
        if (cls.isArray()) {
            javaType_fromWellKnownClass = ArrayType.construct(_fromAny(classStack2, cls.getComponentType(), typeBindings), typeBindings);
            typeFactory = this;
        } else {
            if (cls.isInterface()) {
                javaTypeArr_resolveSuperInterfaces = _resolveSuperInterfaces(classStack2, cls, typeBindings);
            } else {
                javaType_resolveSuperClass = _resolveSuperClass(classStack2, cls, typeBindings);
                javaTypeArr_resolveSuperInterfaces = _resolveSuperInterfaces(classStack2, cls, typeBindings);
            }
            JavaType[] javaTypeArr = javaTypeArr_resolveSuperInterfaces;
            JavaType javaType = javaType_resolveSuperClass;
            if (cls == Properties.class) {
                SimpleType simpleType = CORE_TYPE_STRING;
                cls2 = cls;
                typeBindings2 = typeBindings;
                javaTypeRefine = MapType.construct(cls2, typeBindings2, javaType, javaTypeArr, simpleType, simpleType);
            } else {
                cls2 = cls;
                typeBindings2 = typeBindings;
                if (javaType != null) {
                    javaTypeRefine = javaType.refine(cls2, typeBindings2, javaType, javaTypeArr);
                }
            }
            typeFactory = this;
            if (javaTypeRefine == null) {
                javaType_fromWellKnownClass = typeFactory._fromWellKnownClass(classStack2, cls2, typeBindings2, javaType, javaTypeArr);
                typeFactory = this;
                if (javaType_fromWellKnownClass == null && (javaType_fromWellKnownClass = typeFactory._fromWellKnownInterface(classStack2, cls2, typeBindings2, javaType, javaTypeArr)) == null) {
                    javaType_fromWellKnownClass = _newSimpleType(cls2, typeBindings2, javaType, javaTypeArr);
                }
            } else {
                javaType_fromWellKnownClass = javaTypeRefine;
            }
        }
        classStack2.resolveSelfReferences(javaType_fromWellKnownClass);
        if (objAsKey != null && !javaType_fromWellKnownClass.hasHandlers()) {
            typeFactory._typeCache.putIfAbsent(objAsKey, javaType_fromWellKnownClass);
        }
        return javaType_fromWellKnownClass;
    }

    public JavaType _fromParamType(ClassStack classStack, ParameterizedType parameterizedType, TypeBindings typeBindings) {
        TypeBindings typeBindingsCreate;
        Class<?> cls = (Class) parameterizedType.getRawType();
        if (cls == CLS_ENUM) {
            return CORE_TYPE_ENUM;
        }
        if (cls == CLS_COMPARABLE) {
            return CORE_TYPE_COMPARABLE;
        }
        Type[] actualTypeArguments = parameterizedType.getActualTypeArguments();
        int length = actualTypeArguments == null ? 0 : actualTypeArguments.length;
        if (length == 0) {
            typeBindingsCreate = EMPTY_BINDINGS;
        } else {
            JavaType[] javaTypeArr = new JavaType[length];
            for (int i = 0; i < length; i++) {
                javaTypeArr[i] = _fromAny(classStack, actualTypeArguments[i], typeBindings);
            }
            typeBindingsCreate = TypeBindings.create(cls, javaTypeArr);
        }
        return _fromClass(classStack, cls, typeBindingsCreate);
    }

    public JavaType _fromVariable(ClassStack classStack, TypeVariable<?> typeVariable, TypeBindings typeBindings) {
        Type[] bounds;
        String name = typeVariable.getName();
        if (typeBindings == null) {
            throw new IllegalArgumentException(a.B("Null `bindings` passed (type variable \"", name, "\")"));
        }
        JavaType javaTypeFindBoundType = typeBindings.findBoundType(name);
        if (javaTypeFindBoundType != null) {
            return javaTypeFindBoundType;
        }
        if (typeBindings.hasUnbound(name)) {
            return CORE_TYPE_OBJECT;
        }
        TypeBindings typeBindingsWithUnboundVariable = typeBindings.withUnboundVariable(name);
        synchronized (typeVariable) {
            bounds = typeVariable.getBounds();
        }
        return _fromAny(classStack, bounds[0], typeBindingsWithUnboundVariable);
    }

    public JavaType _fromWellKnownClass(ClassStack classStack, Class<?> cls, TypeBindings typeBindings, JavaType javaType, JavaType[] javaTypeArr) {
        if (typeBindings == null) {
            typeBindings = EMPTY_BINDINGS;
        }
        TypeBindings typeBindings2 = typeBindings;
        if (cls == Map.class) {
            return _mapType(cls, typeBindings2, javaType, javaTypeArr);
        }
        if (cls == Collection.class) {
            return _collectionType(cls, typeBindings2, javaType, javaTypeArr);
        }
        if (cls == AtomicReference.class) {
            return _referenceType(cls, typeBindings2, javaType, javaTypeArr);
        }
        if (cls == Iterator.class || cls == Stream.class) {
            return _iterationType(cls, typeBindings2, javaType, javaTypeArr);
        }
        if (BaseStream.class.isAssignableFrom(cls)) {
            if (DoubleStream.class.isAssignableFrom(cls)) {
                return _iterationType(cls, typeBindings2, javaType, javaTypeArr, CORE_TYPE_DOUBLE);
            }
            if (IntStream.class.isAssignableFrom(cls)) {
                return _iterationType(cls, typeBindings2, javaType, javaTypeArr, CORE_TYPE_INT);
            }
            if (LongStream.class.isAssignableFrom(cls)) {
                return _iterationType(cls, typeBindings2, javaType, javaTypeArr, CORE_TYPE_LONG);
            }
        }
        return null;
    }

    public JavaType _fromWellKnownInterface(ClassStack classStack, Class<?> cls, TypeBindings typeBindings, JavaType javaType, JavaType[] javaTypeArr) {
        for (JavaType javaType2 : javaTypeArr) {
            JavaType javaTypeRefine = javaType2.refine(cls, typeBindings, javaType, javaTypeArr);
            if (javaTypeRefine != null) {
                return javaTypeRefine;
            }
        }
        return null;
    }

    public JavaType _fromWildcard(ClassStack classStack, WildcardType wildcardType, TypeBindings typeBindings) {
        return _fromAny(classStack, wildcardType.getUpperBounds()[0], typeBindings);
    }

    public JavaType _newSimpleType(Class<?> cls, TypeBindings typeBindings, JavaType javaType, JavaType[] javaTypeArr) {
        return new SimpleType(cls, typeBindings, javaType, javaTypeArr);
    }

    public JavaType _resolveSuperClass(ClassStack classStack, Class<?> cls, TypeBindings typeBindings) {
        Type genericSuperclass = ClassUtil.getGenericSuperclass(cls);
        if (genericSuperclass == null) {
            return null;
        }
        return _fromAny(classStack, genericSuperclass, typeBindings);
    }

    public JavaType[] _resolveSuperInterfaces(ClassStack classStack, Class<?> cls, TypeBindings typeBindings) {
        Type[] genericInterfaces = ClassUtil.getGenericInterfaces(cls);
        if (genericInterfaces == null || genericInterfaces.length == 0) {
            return NO_TYPES;
        }
        int length = genericInterfaces.length;
        JavaType[] javaTypeArr = new JavaType[length];
        for (int i = 0; i < length; i++) {
            javaTypeArr[i] = _fromAny(classStack, genericInterfaces[i], typeBindings);
        }
        return javaTypeArr;
    }

    public JavaType _unknownType() {
        return CORE_TYPE_OBJECT;
    }

    public Class<?> classForName(String str, boolean z, ClassLoader classLoader) throws ClassNotFoundException {
        return Class.forName(str, true, classLoader);
    }

    public CollectionType constructCollectionType(Class<? extends Collection> cls, Class<?> cls2) {
        return constructCollectionType(cls, _fromClass(null, cls2, EMPTY_BINDINGS));
    }

    public JavaType constructFromCanonical(String str) throws IllegalArgumentException {
        return this._parser.parse(str);
    }

    public JavaType constructGeneralizedType(JavaType javaType, Class<?> cls) {
        Class<?> rawClass = javaType.getRawClass();
        if (rawClass == cls) {
            return javaType;
        }
        JavaType javaTypeFindSuperType = javaType.findSuperType(cls);
        if (javaTypeFindSuperType != null) {
            return javaTypeFindSuperType;
        }
        if (cls.isAssignableFrom(rawClass)) {
            throw new IllegalArgumentException(String.format("Internal error: class %s not included as super-type for %s", cls.getName(), javaType));
        }
        throw new IllegalArgumentException(String.format("Class %s not a super-type of %s", cls.getName(), javaType));
    }

    public MapType constructMapType(Class<? extends Map> cls, Class<?> cls2, Class<?> cls3) {
        JavaType javaType_fromClass;
        JavaType javaType_fromClass2;
        if (cls == Properties.class) {
            javaType_fromClass = CORE_TYPE_STRING;
            javaType_fromClass2 = javaType_fromClass;
        } else {
            TypeBindings typeBindings = EMPTY_BINDINGS;
            javaType_fromClass = _fromClass(null, cls2, typeBindings);
            javaType_fromClass2 = _fromClass(null, cls3, typeBindings);
        }
        return constructMapType(cls, javaType_fromClass, javaType_fromClass2);
    }

    public JavaType constructParametricType(Class<?> cls, Class<?>... clsArr) {
        int length = clsArr.length;
        JavaType[] javaTypeArr = new JavaType[length];
        for (int i = 0; i < length; i++) {
            javaTypeArr[i] = _fromClass(null, clsArr[i], EMPTY_BINDINGS);
        }
        return constructParametricType(cls, javaTypeArr);
    }

    public JavaType constructSpecializedType(JavaType javaType, Class<?> cls) throws IllegalArgumentException {
        return constructSpecializedType(javaType, cls, false);
    }

    public JavaType constructType(Type type) {
        return _fromAny(null, type, EMPTY_BINDINGS);
    }

    public Class<?> findClass(String str) throws ClassNotFoundException {
        Throwable rootCause;
        Class<?> cls_findPrimitive;
        if (str.indexOf(46) < 0 && (cls_findPrimitive = _findPrimitive(str)) != null) {
            return cls_findPrimitive;
        }
        ClassLoader classLoader = getClassLoader();
        if (classLoader == null) {
            classLoader = Thread.currentThread().getContextClassLoader();
        }
        if (classLoader != null) {
            try {
                return classForName(str, true, classLoader);
            } catch (Exception e) {
                rootCause = ClassUtil.getRootCause(e);
            }
        } else {
            rootCause = null;
        }
        try {
            return classForName(str);
        } catch (Exception e2) {
            if (rootCause == null) {
                rootCause = ClassUtil.getRootCause(e2);
            }
            ClassUtil.throwIfRTE(rootCause);
            throw new ClassNotFoundException(rootCause.getMessage(), rootCause);
        }
    }

    public JavaType[] findTypeParameters(JavaType javaType, Class<?> cls) {
        JavaType javaTypeFindSuperType = javaType.findSuperType(cls);
        return javaTypeFindSuperType == null ? NO_TYPES : javaTypeFindSuperType.getBindings().typeParameterArray();
    }

    public ClassLoader getClassLoader() {
        return this._classLoader;
    }

    public JavaType resolveMemberType(Type type, TypeBindings typeBindings) {
        return _fromAny(null, type, typeBindings);
    }

    @Deprecated
    public JavaType uncheckedSimpleType(Class<?> cls) {
        return _constructSimple(cls, EMPTY_BINDINGS, null, null);
    }

    public TypeFactory(LookupCache<Object, JavaType> lookupCache) {
        Objects.requireNonNull(lookupCache);
        this._typeCache = lookupCache;
        this._parser = new TypeParser(this);
        this._modifiers = null;
        this._classLoader = null;
    }

    public Class<?> classForName(String str) throws ClassNotFoundException {
        return Class.forName(str);
    }

    /* JADX WARN: Code restructure failed: missing block: B:35:0x0060, code lost:
    
        if (r0 == java.util.EnumSet.class) goto L36;
     */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0070  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.fasterxml.jackson.databind.JavaType constructSpecializedType(com.fasterxml.jackson.databind.JavaType r4, java.lang.Class<?> r5, boolean r6) throws java.lang.IllegalArgumentException {
        /*
            r3 = this;
            java.lang.Class r0 = r4.getRawClass()
            if (r0 != r5) goto L7
            goto L62
        L7:
            java.lang.Class<java.lang.Object> r1 = java.lang.Object.class
            r2 = 0
            if (r0 != r1) goto L14
            com.fasterxml.jackson.databind.type.TypeBindings r6 = com.fasterxml.jackson.databind.type.TypeFactory.EMPTY_BINDINGS
            com.fasterxml.jackson.databind.JavaType r5 = r3._fromClass(r2, r5, r6)
            goto L97
        L14:
            boolean r1 = r0.isAssignableFrom(r5)
            if (r1 == 0) goto L9c
            boolean r1 = r4.isContainerType()
            if (r1 == 0) goto L70
            boolean r1 = r4.isMapLikeType()
            if (r1 == 0) goto L47
            java.lang.Class<java.util.HashMap> r0 = java.util.HashMap.class
            if (r5 == r0) goto L36
            java.lang.Class<java.util.LinkedHashMap> r0 = java.util.LinkedHashMap.class
            if (r5 == r0) goto L36
            java.lang.Class<java.util.EnumMap> r0 = java.util.EnumMap.class
            if (r5 == r0) goto L36
            java.lang.Class<java.util.TreeMap> r0 = java.util.TreeMap.class
            if (r5 != r0) goto L70
        L36:
            com.fasterxml.jackson.databind.JavaType r6 = r4.getKeyType()
            com.fasterxml.jackson.databind.JavaType r0 = r4.getContentType()
            com.fasterxml.jackson.databind.type.TypeBindings r6 = com.fasterxml.jackson.databind.type.TypeBindings.create(r5, r6, r0)
            com.fasterxml.jackson.databind.JavaType r5 = r3._fromClass(r2, r5, r6)
            goto L97
        L47:
            boolean r1 = r4.isCollectionLikeType()
            if (r1 == 0) goto L70
            java.lang.Class<java.util.ArrayList> r1 = java.util.ArrayList.class
            if (r5 == r1) goto L63
            java.lang.Class<java.util.LinkedList> r1 = java.util.LinkedList.class
            if (r5 == r1) goto L63
            java.lang.Class<java.util.HashSet> r1 = java.util.HashSet.class
            if (r5 == r1) goto L63
            java.lang.Class<java.util.TreeSet> r1 = java.util.TreeSet.class
            if (r5 != r1) goto L5e
            goto L63
        L5e:
            java.lang.Class<java.util.EnumSet> r1 = java.util.EnumSet.class
            if (r0 != r1) goto L70
        L62:
            return r4
        L63:
            com.fasterxml.jackson.databind.JavaType r6 = r4.getContentType()
            com.fasterxml.jackson.databind.type.TypeBindings r6 = com.fasterxml.jackson.databind.type.TypeBindings.create(r5, r6)
            com.fasterxml.jackson.databind.JavaType r5 = r3._fromClass(r2, r5, r6)
            goto L97
        L70:
            com.fasterxml.jackson.databind.type.TypeBindings r0 = r4.getBindings()
            boolean r0 = r0.isEmpty()
            if (r0 == 0) goto L81
            com.fasterxml.jackson.databind.type.TypeBindings r6 = com.fasterxml.jackson.databind.type.TypeFactory.EMPTY_BINDINGS
            com.fasterxml.jackson.databind.JavaType r5 = r3._fromClass(r2, r5, r6)
            goto L97
        L81:
            java.lang.reflect.TypeVariable[] r0 = r5.getTypeParameters()
            int r0 = r0.length
            if (r0 != 0) goto L8f
            com.fasterxml.jackson.databind.type.TypeBindings r6 = com.fasterxml.jackson.databind.type.TypeFactory.EMPTY_BINDINGS
            com.fasterxml.jackson.databind.JavaType r5 = r3._fromClass(r2, r5, r6)
            goto L97
        L8f:
            com.fasterxml.jackson.databind.type.TypeBindings r6 = r3._bindingsForSubtype(r4, r0, r5, r6)
            com.fasterxml.jackson.databind.JavaType r5 = r3._fromClass(r2, r5, r6)
        L97:
            com.fasterxml.jackson.databind.JavaType r4 = r5.withHandlersFrom(r4)
            return r4
        L9c:
            java.lang.IllegalArgumentException r6 = new java.lang.IllegalArgumentException
            java.lang.String r5 = com.fasterxml.jackson.databind.util.ClassUtil.nameOf(r5)
            java.lang.String r4 = com.fasterxml.jackson.databind.util.ClassUtil.getTypeDescription(r4)
            java.lang.String r0 = "Class "
            java.lang.String r1 = " not subtype of "
            java.lang.String r4 = android.support.v4.media.session.a.m(r0, r5, r1, r4)
            r6.<init>(r4)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.type.TypeFactory.constructSpecializedType(com.fasterxml.jackson.databind.JavaType, java.lang.Class, boolean):com.fasterxml.jackson.databind.JavaType");
    }

    public CollectionType constructCollectionType(Class<? extends Collection> cls, JavaType javaType) {
        TypeBindings typeBindingsCreateIfNeeded = TypeBindings.createIfNeeded(cls, javaType);
        CollectionType collectionType = (CollectionType) _fromClass(null, cls, typeBindingsCreateIfNeeded);
        if (typeBindingsCreateIfNeeded.isEmpty() && javaType != null) {
            JavaType contentType = collectionType.findSuperType(Collection.class).getContentType();
            if (!contentType.equals(javaType)) {
                throw new IllegalArgumentException(String.format("Non-generic Collection class %s did not resolve to something with element type %s but %s ", ClassUtil.nameOf(cls), javaType, contentType));
            }
        }
        return collectionType;
    }

    public JavaType constructParametricType(Class<?> cls, JavaType... javaTypeArr) {
        return constructParametricType(cls, TypeBindings.create(cls, javaTypeArr));
    }

    public MapType constructMapType(Class<? extends Map> cls, JavaType javaType, JavaType javaType2) {
        TypeBindings typeBindingsCreateIfNeeded = TypeBindings.createIfNeeded(cls, new JavaType[]{javaType, javaType2});
        MapType mapType = (MapType) _fromClass(null, cls, typeBindingsCreateIfNeeded);
        if (typeBindingsCreateIfNeeded.isEmpty()) {
            JavaType javaTypeFindSuperType = mapType.findSuperType(Map.class);
            JavaType keyType = javaTypeFindSuperType.getKeyType();
            if (keyType.equals(javaType)) {
                JavaType contentType = javaTypeFindSuperType.getContentType();
                if (!contentType.equals(javaType2)) {
                    throw new IllegalArgumentException(String.format("Non-generic Map class %s did not resolve to something with value type %s but %s ", ClassUtil.nameOf(cls), javaType2, contentType));
                }
            } else {
                throw new IllegalArgumentException(String.format("Non-generic Map class %s did not resolve to something with key type %s but %s ", ClassUtil.nameOf(cls), javaType, keyType));
            }
        }
        return mapType;
    }

    public JavaType constructParametricType(Class<?> cls, TypeBindings typeBindings) {
        return _applyModifiers(cls, _fromClass(null, cls, typeBindings));
    }

    private JavaType _iterationType(Class<?> cls, TypeBindings typeBindings, JavaType javaType, JavaType[] javaTypeArr, JavaType javaType2) {
        return IterationType.construct(cls, typeBindings, javaType, javaTypeArr, javaType2);
    }
}
