package com.fasterxml.jackson.databind.deser.impl;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.databind.util.Converter;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* loaded from: classes.dex */
public abstract class JavaUtilCollectionsDeserializers {

    public static class JavaUtilCollectionsConverter implements Converter<Object, Object> {
        private final JavaType _inputType;
        private final int _kind;

        public JavaUtilCollectionsConverter(int i, JavaType javaType) {
            this._inputType = javaType;
            this._kind = i;
        }

        private void _checkSingleton(int i) {
            if (i != 1) {
                throw new IllegalArgumentException(AbstractC0147y.c(i, "Can not deserialize Singleton container from ", " entries"));
            }
        }

        @Override // com.fasterxml.jackson.databind.util.Converter
        public Object convert(Object obj) {
            if (obj == null) {
                return null;
            }
            switch (this._kind) {
                case 1:
                    Set set = (Set) obj;
                    _checkSingleton(set.size());
                    return Collections.singleton(set.iterator().next());
                case 2:
                    List list = (List) obj;
                    _checkSingleton(list.size());
                    return Collections.singletonList(list.get(0));
                case 3:
                    Map map = (Map) obj;
                    _checkSingleton(map.size());
                    Map.Entry entry = (Map.Entry) map.entrySet().iterator().next();
                    return Collections.singletonMap(entry.getKey(), entry.getValue());
                case 4:
                    return Collections.unmodifiableSet((Set) obj);
                case 5:
                    return Collections.unmodifiableList((List) obj);
                case 6:
                    return Collections.unmodifiableMap((Map) obj);
                case 7:
                    return Collections.synchronizedSet((Set) obj);
                case 8:
                    return Collections.synchronizedCollection((Collection) obj);
                case 9:
                    return Collections.synchronizedList((List) obj);
                case 10:
                    return Collections.synchronizedMap((Map) obj);
                default:
                    return obj;
            }
        }

        @Override // com.fasterxml.jackson.databind.util.Converter
        public JavaType getInputType(TypeFactory typeFactory) {
            return this._inputType;
        }

        @Override // com.fasterxml.jackson.databind.util.Converter
        public JavaType getOutputType(TypeFactory typeFactory) {
            return this._inputType;
        }
    }

    private static String _findSingletonTypeName(String str) {
        if (str.startsWith("Singleton")) {
            return str.substring(9);
        }
        return null;
    }

    private static String _findSyncTypeName(String str) {
        if (str.startsWith("Synchronized")) {
            return str.substring(12);
        }
        return null;
    }

    private static String _findUnmodifiableTypeName(String str) {
        if (str.startsWith("Unmodifiable")) {
            return str.substring(12);
        }
        return null;
    }

    private static String _findUtilArrayTypeName(String str) {
        if (str.startsWith("java.util.Arrays$")) {
            return str.substring(17);
        }
        return null;
    }

    private static String _findUtilCollectionsImmutableTypeName(String str) {
        if (str.startsWith("java.util.ImmutableCollections$")) {
            return str.substring(31);
        }
        return null;
    }

    private static String _findUtilCollectionsTypeName(String str) {
        if (str.startsWith("java.util.Collections$")) {
            return str.substring(22);
        }
        return null;
    }

    public static JavaUtilCollectionsConverter converter(int i, JavaType javaType, Class<?> cls) {
        return new JavaUtilCollectionsConverter(i, javaType.findSuperType(cls));
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x008c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.fasterxml.jackson.databind.JsonDeserializer<?> findForCollection(com.fasterxml.jackson.databind.DeserializationContext r8, com.fasterxml.jackson.databind.JavaType r9) throws com.fasterxml.jackson.databind.JsonMappingException {
        /*
            java.lang.Class r8 = r9.getRawClass()
            java.lang.String r8 = r8.getName()
            java.lang.String r0 = "java.util."
            boolean r0 = r8.startsWith(r0)
            r1 = 0
            if (r0 != 0) goto L12
            return r1
        L12:
            java.lang.String r0 = _findUtilCollectionsTypeName(r8)
            r2 = 4
            java.lang.Class<java.util.Set> r3 = java.util.Set.class
            java.lang.String r4 = "Set"
            java.lang.Class<java.util.List> r5 = java.util.List.class
            java.lang.String r6 = "List"
            if (r0 == 0) goto L96
            java.lang.String r8 = _findUnmodifiableTypeName(r0)
            if (r8 == 0) goto L3e
            boolean r0 = r8.endsWith(r4)
            if (r0 == 0) goto L32
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r8 = converter(r2, r9, r3)
            goto L8d
        L32:
            boolean r8 = r8.endsWith(r6)
            if (r8 == 0) goto L8c
            r8 = 5
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r8 = converter(r8, r9, r5)
            goto L8d
        L3e:
            java.lang.String r8 = _findSingletonTypeName(r0)
            if (r8 == 0) goto L5c
            boolean r0 = r8.endsWith(r4)
            if (r0 == 0) goto L50
            r8 = 1
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r8 = converter(r8, r9, r3)
            goto L8d
        L50:
            boolean r8 = r8.endsWith(r6)
            if (r8 == 0) goto L8c
            r8 = 2
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r8 = converter(r8, r9, r5)
            goto L8d
        L5c:
            java.lang.String r8 = _findSyncTypeName(r0)
            if (r8 == 0) goto L8c
            boolean r0 = r8.endsWith(r4)
            if (r0 == 0) goto L6e
            r8 = 7
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r8 = converter(r8, r9, r3)
            goto L8d
        L6e:
            boolean r0 = r8.endsWith(r6)
            if (r0 == 0) goto L7b
            r8 = 9
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r8 = converter(r8, r9, r5)
            goto L8d
        L7b:
            java.lang.String r0 = "Collection"
            boolean r8 = r8.endsWith(r0)
            if (r8 == 0) goto L8c
            r8 = 8
            java.lang.Class<java.util.Collection> r0 = java.util.Collection.class
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r8 = converter(r8, r9, r0)
            goto L8d
        L8c:
            r8 = r1
        L8d:
            if (r8 != 0) goto L90
            return r1
        L90:
            com.fasterxml.jackson.databind.deser.std.StdDelegatingDeserializer r9 = new com.fasterxml.jackson.databind.deser.std.StdDelegatingDeserializer
            r9.<init>(r8)
            return r9
        L96:
            java.lang.String r0 = _findUtilArrayTypeName(r8)
            r7 = 11
            if (r0 == 0) goto Laf
            boolean r8 = r0.contains(r6)
            if (r8 == 0) goto Lae
            com.fasterxml.jackson.databind.deser.std.StdDelegatingDeserializer r8 = new com.fasterxml.jackson.databind.deser.std.StdDelegatingDeserializer
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r9 = converter(r7, r9, r5)
            r8.<init>(r9)
            return r8
        Lae:
            return r1
        Laf:
            java.lang.String r8 = _findUtilCollectionsImmutableTypeName(r8)
            if (r8 == 0) goto Ld5
            boolean r0 = r8.contains(r6)
            if (r0 == 0) goto Lc5
            com.fasterxml.jackson.databind.deser.std.StdDelegatingDeserializer r8 = new com.fasterxml.jackson.databind.deser.std.StdDelegatingDeserializer
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r9 = converter(r7, r9, r5)
            r8.<init>(r9)
            return r8
        Lc5:
            boolean r8 = r8.contains(r4)
            if (r8 == 0) goto Ld5
            com.fasterxml.jackson.databind.deser.std.StdDelegatingDeserializer r8 = new com.fasterxml.jackson.databind.deser.std.StdDelegatingDeserializer
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r9 = converter(r2, r9, r3)
            r8.<init>(r9)
            return r8
        Ld5:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers.findForCollection(com.fasterxml.jackson.databind.DeserializationContext, com.fasterxml.jackson.databind.JavaType):com.fasterxml.jackson.databind.JsonDeserializer");
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x005b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.fasterxml.jackson.databind.JsonDeserializer<?> findForMap(com.fasterxml.jackson.databind.DeserializationContext r5, com.fasterxml.jackson.databind.JavaType r6) throws com.fasterxml.jackson.databind.JsonMappingException {
        /*
            java.lang.Class r5 = r6.getRawClass()
            java.lang.String r5 = r5.getName()
            java.lang.String r0 = _findUtilCollectionsTypeName(r5)
            r1 = 6
            java.lang.Class<java.util.Map> r2 = java.util.Map.class
            java.lang.String r3 = "Map"
            r4 = 0
            if (r0 == 0) goto L4a
            java.lang.String r5 = _findUnmodifiableTypeName(r0)
            if (r5 == 0) goto L25
            boolean r5 = r5.contains(r3)
            if (r5 == 0) goto L5b
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r5 = converter(r1, r6, r2)
            goto L5c
        L25:
            java.lang.String r5 = _findSingletonTypeName(r0)
            if (r5 == 0) goto L37
            boolean r5 = r5.contains(r3)
            if (r5 == 0) goto L5b
            r5 = 3
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r5 = converter(r5, r6, r2)
            goto L5c
        L37:
            java.lang.String r5 = _findSyncTypeName(r0)
            if (r5 == 0) goto L5b
            boolean r5 = r5.contains(r3)
            if (r5 == 0) goto L5b
            r5 = 10
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r5 = converter(r5, r6, r2)
            goto L5c
        L4a:
            java.lang.String r5 = _findUtilCollectionsImmutableTypeName(r5)
            if (r5 == 0) goto L5b
            boolean r5 = r5.contains(r3)
            if (r5 == 0) goto L5b
            com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers$JavaUtilCollectionsConverter r5 = converter(r1, r6, r2)
            goto L5c
        L5b:
            r5 = r4
        L5c:
            if (r5 != 0) goto L5f
            return r4
        L5f:
            com.fasterxml.jackson.databind.deser.std.StdDelegatingDeserializer r6 = new com.fasterxml.jackson.databind.deser.std.StdDelegatingDeserializer
            r6.<init>(r5)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.deser.impl.JavaUtilCollectionsDeserializers.findForMap(com.fasterxml.jackson.databind.DeserializationContext, com.fasterxml.jackson.databind.JavaType):com.fasterxml.jackson.databind.JsonDeserializer");
    }
}
