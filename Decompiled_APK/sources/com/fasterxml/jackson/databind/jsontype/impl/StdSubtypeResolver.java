package com.fasterxml.jackson.databind.jsontype.impl;

import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.introspect.AnnotatedClass;
import com.fasterxml.jackson.databind.introspect.AnnotatedClassResolver;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.databind.jsontype.SubtypeResolver;
import java.io.Serializable;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* loaded from: classes.dex */
public class StdSubtypeResolver extends SubtypeResolver implements Serializable {
    protected LinkedHashSet<NamedType> _registeredSubtypes;

    public void _collectAndResolve(AnnotatedClass annotatedClass, NamedType namedType, MapperConfig<?> mapperConfig, AnnotationIntrospector annotationIntrospector, HashMap<NamedType, NamedType> map) {
        String strFindTypeName;
        if (!namedType.hasName() && (strFindTypeName = annotationIntrospector.findTypeName(annotatedClass)) != null) {
            namedType = new NamedType(namedType.getType(), strFindTypeName);
        }
        NamedType namedType2 = new NamedType(namedType.getType());
        if (map.containsKey(namedType2)) {
            if (!namedType.hasName() || map.get(namedType2).hasName()) {
                return;
            }
            map.put(namedType2, namedType);
            return;
        }
        map.put(namedType2, namedType);
        List<NamedType> listFindSubtypes = annotationIntrospector.findSubtypes(annotatedClass);
        if (listFindSubtypes == null || listFindSubtypes.isEmpty()) {
            return;
        }
        for (NamedType namedType3 : listFindSubtypes) {
            _collectAndResolve(AnnotatedClassResolver.resolveWithoutSuperTypes(mapperConfig, namedType3.getType()), namedType3, mapperConfig, annotationIntrospector, map);
        }
    }

    public void _collectAndResolveByTypeId(AnnotatedClass annotatedClass, NamedType namedType, MapperConfig<?> mapperConfig, Set<Class<?>> set, Map<String, NamedType> map) {
        List<NamedType> listFindSubtypes;
        String strFindTypeName;
        AnnotationIntrospector annotationIntrospector = mapperConfig.getAnnotationIntrospector();
        if (!namedType.hasName() && (strFindTypeName = annotationIntrospector.findTypeName(annotatedClass)) != null) {
            namedType = new NamedType(namedType.getType(), strFindTypeName);
        }
        if (namedType.hasName()) {
            map.put(namedType.getName(), namedType);
        }
        if (!set.add(namedType.getType()) || (listFindSubtypes = annotationIntrospector.findSubtypes(annotatedClass)) == null || listFindSubtypes.isEmpty()) {
            return;
        }
        for (NamedType namedType2 : listFindSubtypes) {
            _collectAndResolveByTypeId(AnnotatedClassResolver.resolveWithoutSuperTypes(mapperConfig, namedType2.getType()), namedType2, mapperConfig, set, map);
        }
    }

    public Collection<NamedType> _combineNamedAndUnnamed(Class<?> cls, Set<Class<?>> set, Map<String, NamedType> map) {
        ArrayList arrayList = new ArrayList(map.values());
        Iterator<NamedType> it2 = map.values().iterator();
        while (it2.hasNext()) {
            set.remove(it2.next().getType());
        }
        for (Class<?> cls2 : set) {
            if (cls2 != cls || !Modifier.isAbstract(cls2.getModifiers())) {
                arrayList.add(new NamedType(cls2));
            }
        }
        return arrayList;
    }

    @Override // com.fasterxml.jackson.databind.jsontype.SubtypeResolver
    public Collection<NamedType> collectAndResolveSubtypesByClass(MapperConfig<?> mapperConfig, AnnotatedMember annotatedMember, JavaType javaType) {
        Class<?> rawType;
        List<NamedType> listFindSubtypes;
        MapperConfig<?> mapperConfig2;
        AnnotationIntrospector annotationIntrospector = mapperConfig.getAnnotationIntrospector();
        if (javaType != null) {
            rawType = javaType.getRawClass();
        } else {
            if (annotatedMember == null) {
                throw new IllegalArgumentException("Both property and base type are nulls");
            }
            rawType = annotatedMember.getRawType();
        }
        HashMap<NamedType, NamedType> map = new HashMap<>();
        LinkedHashSet<NamedType> linkedHashSet = this._registeredSubtypes;
        if (linkedHashSet != null) {
            Iterator<NamedType> it2 = linkedHashSet.iterator();
            while (it2.hasNext()) {
                NamedType next = it2.next();
                if (rawType.isAssignableFrom(next.getType())) {
                    mapperConfig2 = mapperConfig;
                    _collectAndResolve(AnnotatedClassResolver.resolveWithoutSuperTypes(mapperConfig, next.getType()), next, mapperConfig2, annotationIntrospector, map);
                } else {
                    mapperConfig2 = mapperConfig;
                }
                mapperConfig = mapperConfig2;
            }
        }
        MapperConfig<?> mapperConfig3 = mapperConfig;
        if (annotatedMember != null && (listFindSubtypes = annotationIntrospector.findSubtypes(annotatedMember)) != null) {
            for (NamedType namedType : listFindSubtypes) {
                _collectAndResolve(AnnotatedClassResolver.resolveWithoutSuperTypes(mapperConfig3, namedType.getType()), namedType, mapperConfig3, annotationIntrospector, map);
            }
        }
        _collectAndResolve(AnnotatedClassResolver.resolveWithoutSuperTypes(mapperConfig3, rawType), new NamedType(rawType, null), mapperConfig3, annotationIntrospector, map);
        return new ArrayList(map.values());
    }

    @Override // com.fasterxml.jackson.databind.jsontype.SubtypeResolver
    public Collection<NamedType> collectAndResolveSubtypesByTypeId(MapperConfig<?> mapperConfig, AnnotatedMember annotatedMember, JavaType javaType) {
        List<NamedType> listFindSubtypes;
        AnnotationIntrospector annotationIntrospector = mapperConfig.getAnnotationIntrospector();
        Class<?> rawClass = javaType.getRawClass();
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        _collectAndResolveByTypeId(AnnotatedClassResolver.resolveWithoutSuperTypes(mapperConfig, rawClass), new NamedType(rawClass, null), mapperConfig, linkedHashSet, linkedHashMap);
        if (annotatedMember != null && (listFindSubtypes = annotationIntrospector.findSubtypes(annotatedMember)) != null) {
            for (NamedType namedType : listFindSubtypes) {
                _collectAndResolveByTypeId(AnnotatedClassResolver.resolveWithoutSuperTypes(mapperConfig, namedType.getType()), namedType, mapperConfig, linkedHashSet, linkedHashMap);
            }
        }
        LinkedHashSet<NamedType> linkedHashSet2 = this._registeredSubtypes;
        if (linkedHashSet2 != null) {
            Iterator<NamedType> it2 = linkedHashSet2.iterator();
            while (it2.hasNext()) {
                NamedType next = it2.next();
                if (rawClass.isAssignableFrom(next.getType())) {
                    _collectAndResolveByTypeId(AnnotatedClassResolver.resolveWithoutSuperTypes(mapperConfig, next.getType()), next, mapperConfig, linkedHashSet, linkedHashMap);
                }
            }
        }
        return _combineNamedAndUnnamed(rawClass, linkedHashSet, linkedHashMap);
    }

    @Override // com.fasterxml.jackson.databind.jsontype.SubtypeResolver
    public Collection<NamedType> collectAndResolveSubtypesByTypeId(MapperConfig<?> mapperConfig, AnnotatedClass annotatedClass) {
        Class<?> rawType = annotatedClass.getRawType();
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        _collectAndResolveByTypeId(annotatedClass, new NamedType(rawType, null), mapperConfig, linkedHashSet, linkedHashMap);
        LinkedHashSet<NamedType> linkedHashSet2 = this._registeredSubtypes;
        if (linkedHashSet2 != null) {
            Iterator<NamedType> it2 = linkedHashSet2.iterator();
            while (it2.hasNext()) {
                NamedType next = it2.next();
                if (rawType.isAssignableFrom(next.getType())) {
                    _collectAndResolveByTypeId(AnnotatedClassResolver.resolveWithoutSuperTypes(mapperConfig, next.getType()), next, mapperConfig, linkedHashSet, linkedHashMap);
                }
            }
        }
        return _combineNamedAndUnnamed(rawType, linkedHashSet, linkedHashMap);
    }

    @Override // com.fasterxml.jackson.databind.jsontype.SubtypeResolver
    public Collection<NamedType> collectAndResolveSubtypesByClass(MapperConfig<?> mapperConfig, AnnotatedClass annotatedClass) {
        MapperConfig<?> mapperConfig2;
        AnnotationIntrospector annotationIntrospector = mapperConfig.getAnnotationIntrospector();
        HashMap<NamedType, NamedType> map = new HashMap<>();
        if (this._registeredSubtypes != null) {
            Class<?> rawType = annotatedClass.getRawType();
            Iterator<NamedType> it2 = this._registeredSubtypes.iterator();
            while (it2.hasNext()) {
                NamedType next = it2.next();
                if (rawType.isAssignableFrom(next.getType())) {
                    mapperConfig2 = mapperConfig;
                    _collectAndResolve(AnnotatedClassResolver.resolveWithoutSuperTypes(mapperConfig, next.getType()), next, mapperConfig2, annotationIntrospector, map);
                } else {
                    mapperConfig2 = mapperConfig;
                }
                mapperConfig = mapperConfig2;
            }
        }
        _collectAndResolve(annotatedClass, new NamedType(annotatedClass.getRawType(), null), mapperConfig, annotationIntrospector, map);
        return new ArrayList(map.values());
    }
}
